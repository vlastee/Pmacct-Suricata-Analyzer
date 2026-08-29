// Package rules is the detection engine: it evaluates rules on a schedule, deduplicates
// findings into alerts and hands new alerts to the notifier. Rules are either built in
// (builtin.go, tunable through RuleConfig overrides) or user-defined (custom.go).
package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/config"
	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// Notifier receives newly raised (or re-raised) alerts.
type Notifier interface {
	Notify(ctx context.Context, alerts []db.Alert)
}

// RuleConfig is the user-adjustable part of a rule. For built-in rules it is stored as an
// override in settings["rules"]; for custom rules the same fields live on the rule's row.
// Fields left empty/nil in an update keep their current value.
type RuleConfig struct {
	Enabled     *bool          `json:"enabled,omitempty"`
	Severity    string         `json:"severity,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
	ExemptHosts []string       `json:"exempt_hosts,omitempty"` // IPs or nicknames
	Interval    string         `json:"interval,omitempty"`     // Go duration ("5m"); how often the rule runs
	Window      string         `json:"window,omitempty"`       // Go duration ("1h"); how far back it looks
}

// Config maps rule name -> overrides.
type Config map[string]RuleConfig

// Param documents one tunable.
type Param struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Default     any    `json:"default"`
}

// Rule describes a detection.
type Rule struct {
	Name        string
	Title       string
	Description string
	Severity    string
	Interval    time.Duration // how often to evaluate
	Window      time.Duration // how far back to look
	Params      []Param
	run         func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error)

	custom *db.CustomRule // non-nil for user-defined rules
	base   *Rule          // custom rules built on a built-in detector
}

// RuleInfo is the API view of a rule with its effective configuration.
type RuleInfo struct {
	Name            string         `json:"name"`
	Title           string         `json:"title"`
	Description     string         `json:"description"`
	Enabled         bool           `json:"enabled"`
	Severity        string         `json:"severity"`
	Interval        string         `json:"interval"`
	Window          string         `json:"window"`
	DefaultSeverity string         `json:"default_severity"`
	DefaultInterval string         `json:"default_interval"`
	DefaultWindow   string         `json:"default_window"`
	Params          []Param        `json:"params"`
	Values          map[string]any `json:"values"`
	ExemptHosts     []string       `json:"exempt_hosts"`
	Custom          bool           `json:"custom"`
	Kind            string         `json:"kind,omitempty"` // custom rules: "sql" | "builtin"
	Base            string         `json:"base,omitempty"` // custom rules of kind builtin
	SQL             string         `json:"sql,omitempty"`  // custom rules of kind sql
	LastRun         *time.Time     `json:"last_run"`
	LastCount       int            `json:"last_findings"`
	LastError       string         `json:"last_error,omitempty"`
	LastMs          int64          `json:"last_ms"`
}

// Timing limits for interval/window overrides.
const (
	MinInterval = 30 * time.Second
	MaxInterval = 7 * 24 * time.Hour
	MinWindow   = time.Minute
	MaxWindow   = 30 * 24 * time.Hour
)

// ErrUnknownRule is returned for a rule name that does not exist.
var ErrUnknownRule = errors.New("unknown rule")

// ValidationError reports bad user input (HTTP 400).
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &ValidationError{Msg: fmt.Sprintf(format, a...)} }

func unknownRule(name string) error { return fmt.Errorf("%w %q", ErrUnknownRule, name) }

// params gives typed access to effective parameter values.
type params map[string]any

func (p params) Int(k string) int {
	switch v := p[k].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

func (p params) Float(k string) float64 {
	switch v := p[k].(type) {
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case float64:
		return v
	case json.Number:
		f, _ := v.Float64()
		return f
	}
	return 0
}

func (p params) Strings(k string) []string {
	switch v := p[k].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			out = append(out, strings.TrimSpace(fmt.Sprint(x)))
		}
		return out
	case string:
		var out []string
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (p params) Ints(k string) []int {
	var out []int
	for _, s := range p.Strings(k) {
		var n int
		if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
			out = append(out, n)
		}
	}
	switch v := p[k].(type) {
	case []int:
		return v
	case []any:
		out = out[:0]
		for _, x := range v {
			switch n := x.(type) {
			case float64:
				out = append(out, int(n))
			case int:
				out = append(out, n)
			case string:
				var i int
				if _, err := fmt.Sscanf(n, "%d", &i); err == nil {
					out = append(out, i)
				}
			}
		}
	}
	return out
}

// Engine evaluates rules.
type Engine struct {
	DB       *db.DB
	Cfg      *config.Config
	Notifier Notifier
	Now      func() time.Time

	mu      sync.Mutex
	builtin []*Rule
	custom  []*Rule
	cfg     Config
	state   map[string]*ruleState
}

type ruleState struct {
	lastRun   time.Time
	lastCount int
	lastErr   string
	lastMs    int64
}

// effective is a rule's configuration after overrides.
type effective struct {
	enabled  bool
	severity string
	params   params
	exempt   []string
	interval time.Duration
	window   time.Duration
}

// New builds an engine with the built-in rules, the stored overrides and the custom rules.
func New(ctx context.Context, d *db.DB, cfg *config.Config, n Notifier) (*Engine, error) {
	e := &Engine{DB: d, Cfg: cfg, Notifier: n, Now: time.Now, builtin: builtinRules(), cfg: Config{}, state: map[string]*ruleState{}}
	for _, r := range e.builtin {
		e.state[r.Name] = &ruleState{}
	}
	if _, err := d.GetSetting(ctx, "rules", &e.cfg); err != nil {
		return nil, fmt.Errorf("load rules config: %w", err)
	}
	if err := e.loadCustom(ctx); err != nil {
		return nil, fmt.Errorf("load custom rules: %w", err)
	}
	return e, nil
}

// Rules returns the rule definitions: built-ins first, then custom rules.
func (e *Engine) Rules() []*Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*Rule, 0, len(e.builtin)+len(e.custom))
	out = append(out, e.builtin...)
	return append(out, e.custom...)
}

func (e *Engine) rule(name string) *Rule {
	for _, r := range e.Rules() {
		if r.Name == name {
			return r
		}
	}
	return nil
}

func (e *Engine) builtinRule(name string) *Rule {
	for _, r := range e.builtin {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// effective merges defaults with overrides.
func (e *Engine) effective(r *Rule) effective {
	if c := r.custom; c != nil {
		p := params{}
		if r.base != nil {
			for _, d := range r.base.Params {
				p[d.Name] = d.Default
			}
		}
		for k, v := range c.Params {
			if _, known := p[k]; known || r.base == nil {
				p[k] = v
			}
		}
		ex := c.ExemptHosts
		if ex == nil {
			ex = []string{}
		}
		return effective{enabled: c.Enabled, severity: c.Severity, params: p, exempt: ex, interval: c.Interval, window: c.Window}
	}
	e.mu.Lock()
	rc := e.cfg[r.Name]
	e.mu.Unlock()
	ef := effective{enabled: true, severity: r.Severity, params: params{}, exempt: rc.ExemptHosts, interval: r.Interval, window: r.Window}
	if rc.Enabled != nil {
		ef.enabled = *rc.Enabled
	}
	if db.SeverityRank(rc.Severity) > 0 {
		ef.severity = rc.Severity
	}
	for _, d := range r.Params {
		ef.params[d.Name] = d.Default
	}
	for k, v := range rc.Params {
		if _, ok := ef.params[k]; ok {
			ef.params[k] = v
		}
	}
	if d, err := time.ParseDuration(rc.Interval); err == nil && d > 0 {
		ef.interval = d
	}
	if d, err := time.ParseDuration(rc.Window); err == nil && d > 0 {
		ef.window = d
	}
	if ef.exempt == nil {
		ef.exempt = []string{}
	}
	return ef
}

// Infos returns API views of all rules.
func (e *Engine) Infos() []RuleInfo {
	rules := e.Rules()
	out := make([]RuleInfo, 0, len(rules))
	for _, r := range rules {
		out = append(out, e.info(r))
	}
	return out
}

func (e *Engine) info(r *Rule) RuleInfo {
	ef := e.effective(r)
	e.mu.Lock()
	st := ruleState{}
	if s := e.state[r.Name]; s != nil {
		st = *s
	}
	e.mu.Unlock()
	info := RuleInfo{Name: r.Name, Title: r.Title, Description: r.Description, Enabled: ef.enabled, Severity: ef.severity,
		Interval: ef.interval.String(), Window: ef.window.String(),
		DefaultSeverity: r.Severity, DefaultInterval: r.Interval.String(), DefaultWindow: r.Window.String(),
		Params: r.Params, Values: ef.params, ExemptHosts: ef.exempt,
		LastCount: st.lastCount, LastError: st.lastErr, LastMs: st.lastMs}
	if info.Params == nil {
		info.Params = []Param{}
	}
	if c := r.custom; c != nil {
		info.Custom, info.Kind, info.Base, info.SQL = true, c.Kind, c.Base, c.SQL
	}
	if !st.lastRun.IsZero() {
		t := st.lastRun
		info.LastRun = &t
	}
	return info
}

// parseTiming validates an interval/window override; "" means "keep the default".
func parseTiming(what, s string, min, max time.Duration) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, invalid("invalid %s %q: use a duration like 30s, 5m, 1h", what, s)
	}
	if d < min || d > max {
		return 0, invalid("%s must be between %s and %s", what, min, max)
	}
	return d, nil
}

// validateConfig checks an update against the rule's definition.
func validateConfig(r *Rule, rc RuleConfig) error {
	if rc.Severity != "" && db.SeverityRank(rc.Severity) == 0 {
		return invalid("invalid severity %q", rc.Severity)
	}
	for k := range rc.Params {
		known := false
		for _, d := range r.Params {
			if d.Name == k {
				known = true
			}
		}
		if !known {
			return invalid("unknown parameter %q for rule %s", k, r.Name)
		}
	}
	if _, err := parseTiming("interval", rc.Interval, MinInterval, MaxInterval); err != nil {
		return err
	}
	if _, err := parseTiming("window", rc.Window, MinWindow, MaxWindow); err != nil {
		return err
	}
	return nil
}

// UpdateConfig validates and persists overrides for one rule. Only the fields present in rc
// change; an interval/window equal to the rule's default clears that override.
func (e *Engine) UpdateConfig(ctx context.Context, name string, rc RuleConfig) error {
	r := e.rule(name)
	if r == nil {
		return unknownRule(name)
	}
	if err := validateConfig(r, rc); err != nil {
		return err
	}
	if r.custom != nil {
		return e.updateCustomConfig(ctx, r, rc)
	}
	e.mu.Lock()
	cur := e.cfg[name]
	if rc.Enabled != nil {
		cur.Enabled = rc.Enabled
	}
	if rc.Severity != "" {
		cur.Severity = rc.Severity
	}
	if rc.Params != nil {
		cur.Params = rc.Params
	}
	if rc.ExemptHosts != nil {
		cur.ExemptHosts = rc.ExemptHosts
	}
	if rc.Interval != "" {
		cur.Interval = rc.Interval
		if d, _ := time.ParseDuration(rc.Interval); d == r.Interval {
			cur.Interval = ""
		}
	}
	if rc.Window != "" {
		cur.Window = rc.Window
		if d, _ := time.ParseDuration(rc.Window); d == r.Window {
			cur.Window = ""
		}
	}
	e.cfg[name] = cur
	snapshot := Config{}
	for k, v := range e.cfg {
		snapshot[k] = v
	}
	e.mu.Unlock()
	return e.DB.SetSetting(ctx, "rules", snapshot)
}

// Run loops until ctx is done.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(e.Cfg.RulesInterval)
	defer t.Stop()
	e.Tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Tick(ctx)
		}
	}
}

// Tick evaluates every enabled rule whose interval has elapsed.
func (e *Engine) Tick(ctx context.Context) {
	now := e.Now()
	for _, r := range e.Rules() {
		ef := e.effective(r)
		e.mu.Lock()
		st := e.state[r.Name]
		due := st == nil || st.lastRun.IsZero() || now.Sub(st.lastRun) >= ef.interval
		e.mu.Unlock()
		if !due {
			continue
		}
		if _, err := e.RunRule(ctx, r.Name, false); err != nil && ctx.Err() == nil {
			slog.Error("rule failed", "rule", r.Name, "err", err)
		}
	}
	if n, err := e.DB.AutoResolveStale(ctx, 7*24*time.Hour); err == nil && n > 0 {
		slog.Info("auto-resolved stale alerts", "n", n)
	}
}

// evaluate runs a rule's detector over its window and applies exemptions/defaults to the
// findings, without touching alerts or notifications.
func (e *Engine) evaluate(ctx context.Context, r *Rule) ([]db.Finding, effective, error) {
	ef := e.effective(r)
	until := e.Now().UTC()
	w := db.Window{Since: until.Add(-ef.window), Until: until}
	findings, err := r.run(ctx, e, r, ef.params, w)
	if err != nil {
		return nil, ef, err
	}
	set, err := e.resolveExempt(ctx, ef.exempt)
	if err != nil {
		return nil, ef, err
	}
	kept := make([]db.Finding, 0, len(findings))
	for _, f := range findings {
		if set[f.Host] || set[f.Peer] {
			continue
		}
		f.Rule = r.Name
		if f.Severity == "" {
			f.Severity = ef.severity
		}
		if f.Title == "" {
			f.Title = defaultTitle(r, f)
		}
		if f.Details == nil {
			f.Details = map[string]any{}
		}
		kept = append(kept, f)
	}
	return kept, ef, nil
}

func defaultTitle(r *Rule, f db.Finding) string {
	who := f.Host
	if who == "" {
		who = f.Peer
	} else if f.Peer != "" {
		who += " → " + f.Peer
	}
	if f.Port > 0 {
		who += fmt.Sprintf(":%d", f.Port)
	}
	return r.Title + ": " + who
}

// RunRule evaluates one rule now (force ignores the enabled flag; used by the API for testing)
// and returns the alerts that were raised or re-raised.
func (e *Engine) RunRule(ctx context.Context, name string, force bool) ([]db.Alert, error) {
	r := e.rule(name)
	if r == nil {
		return nil, unknownRule(name)
	}
	e.mu.Lock()
	st := e.state[r.Name]
	if st == nil {
		st = &ruleState{}
		e.state[r.Name] = st
	}
	st.lastRun = e.Now()
	e.mu.Unlock()
	if !e.effective(r).enabled && !force {
		return nil, nil
	}
	start := time.Now()
	findings, _, err := e.evaluate(ctx, r)
	e.mu.Lock()
	st.lastMs = time.Since(start).Milliseconds()
	if err != nil {
		st.lastErr = err.Error()
	} else {
		st.lastErr = ""
	}
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var raised []db.Alert
	for _, f := range findings {
		a, err := e.DB.UpsertAlert(ctx, f)
		if err != nil {
			return nil, fmt.Errorf("upsert alert: %w", err)
		}
		if a.Inserted || a.NotifiedAt == nil || e.Now().Sub(*a.NotifiedAt) > e.Cfg.NotifyRenotifyAfter {
			raised = append(raised, *a)
		}
	}
	e.mu.Lock()
	st.lastCount = len(findings)
	e.mu.Unlock()
	if len(raised) > 0 && e.Notifier != nil {
		e.Notifier.Notify(ctx, raised)
	}
	return raised, nil
}

// Preview evaluates a saved rule and returns what it would raise, without creating alerts.
func (e *Engine) Preview(ctx context.Context, name string) ([]db.Finding, error) {
	r := e.rule(name)
	if r == nil {
		return nil, unknownRule(name)
	}
	findings, _, err := e.evaluate(ctx, r)
	if findings == nil && err == nil {
		findings = []db.Finding{}
	}
	return findings, err
}

// resolveExempt turns IPs/nicknames into a set of IP strings.
func (e *Engine) resolveExempt(ctx context.Context, list []string) (map[string]bool, error) {
	set := map[string]bool{}
	if len(list) == 0 {
		return set, nil
	}
	var names []string
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if a, err := netip.ParseAddr(item); err == nil {
			set[a.Unmap().String()] = true
		} else {
			names = append(names, strings.ToLower(item))
		}
	}
	if len(names) > 0 {
		all, err := e.DB.ListNicknames(ctx, "")
		if err != nil {
			return nil, err
		}
		for _, n := range all {
			for _, want := range names {
				if strings.ToLower(n.Nickname) == want {
					set[n.IP] = true
				}
			}
		}
	}
	return set, nil
}

// gatewayList returns configured gateways as strings (exempt from DNS-style rules).
func (e *Engine) gatewayList() []string {
	out := []string{}
	for _, g := range e.Cfg.Gateways {
		out = append(out, g.String())
	}
	return out
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RaiseIDS stores an IDS-derived finding through the "ids" pseudo-rule (honours enabled/exemptions).
func (e *Engine) RaiseIDS(ctx context.Context, f db.Finding) error {
	r := e.builtinRule("ids")
	ef := e.effective(r)
	if !ef.enabled {
		return nil
	}
	if sev, ok := f.Details["suricata_severity"].(int); ok && sev > ef.params.Int("min_suricata_severity") {
		return nil
	}
	set, err := e.resolveExempt(ctx, ef.exempt)
	if err != nil {
		return err
	}
	if set[f.Host] || set[f.Peer] {
		return nil
	}
	f.Rule = "ids"
	a, err := e.DB.UpsertAlert(ctx, f)
	if err != nil {
		return err
	}
	if e.Notifier != nil && (a.Inserted || a.NotifiedAt == nil || e.Now().Sub(*a.NotifiedAt) > e.Cfg.NotifyRenotifyAfter) {
		e.Notifier.Notify(ctx, []db.Alert{*a})
	}
	return nil
}

func logWarn(msg string, err error) { slog.Warn(msg, "err", err) }
