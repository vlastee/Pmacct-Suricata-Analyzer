// Package rules is the detection engine: it evaluates rules on a schedule, deduplicates
// findings into alerts and hands new alerts to the notifier.
package rules

import (
	"context"
	"encoding/json"
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

// RuleConfig is the user-adjustable part of a rule, stored in settings["rules"].
type RuleConfig struct {
	Enabled     *bool          `json:"enabled,omitempty"`
	Severity    string         `json:"severity,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
	ExemptHosts []string       `json:"exempt_hosts,omitempty"` // IPs or nicknames
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
}

// RuleInfo is the API view of a rule with its effective configuration.
type RuleInfo struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Enabled     bool           `json:"enabled"`
	Severity    string         `json:"severity"`
	Interval    string         `json:"interval"`
	Window      string         `json:"window"`
	Params      []Param        `json:"params"`
	Values      map[string]any `json:"values"`
	ExemptHosts []string       `json:"exempt_hosts"`
	LastRun     *time.Time     `json:"last_run"`
	LastCount   int            `json:"last_findings"`
	LastError   string         `json:"last_error,omitempty"`
	LastMs      int64          `json:"last_ms"`
}

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

	rules []*Rule
	mu    sync.Mutex
	cfg   Config
	state map[string]*ruleState
}

type ruleState struct {
	lastRun   time.Time
	lastCount int
	lastErr   string
	lastMs    int64
}

// New builds an engine with the built-in rules and loads the stored configuration.
func New(ctx context.Context, d *db.DB, cfg *config.Config, n Notifier) (*Engine, error) {
	e := &Engine{DB: d, Cfg: cfg, Notifier: n, Now: time.Now, rules: builtinRules(), state: map[string]*ruleState{}}
	for _, r := range e.rules {
		e.state[r.Name] = &ruleState{}
	}
	e.cfg = Config{}
	if _, err := d.GetSetting(ctx, "rules", &e.cfg); err != nil {
		return nil, fmt.Errorf("load rules config: %w", err)
	}
	return e, nil
}

// Rules returns the rule definitions.
func (e *Engine) Rules() []*Rule { return e.rules }

func (e *Engine) rule(name string) *Rule {
	for _, r := range e.rules {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// effective merges defaults with overrides.
func (e *Engine) effective(r *Rule) (enabled bool, severity string, p params, exempt []string) {
	e.mu.Lock()
	rc := e.cfg[r.Name]
	e.mu.Unlock()
	enabled = true
	if rc.Enabled != nil {
		enabled = *rc.Enabled
	}
	severity = r.Severity
	if db.SeverityRank(rc.Severity) > 0 {
		severity = rc.Severity
	}
	p = params{}
	for _, d := range r.Params {
		p[d.Name] = d.Default
	}
	for k, v := range rc.Params {
		if _, ok := p[k]; ok {
			p[k] = v
		}
	}
	return enabled, severity, p, rc.ExemptHosts
}

// Infos returns API views of all rules.
func (e *Engine) Infos() []RuleInfo {
	out := make([]RuleInfo, 0, len(e.rules))
	for _, r := range e.rules {
		enabled, sev, p, exempt := e.effective(r)
		e.mu.Lock()
		st := *e.state[r.Name]
		e.mu.Unlock()
		info := RuleInfo{Name: r.Name, Title: r.Title, Description: r.Description, Enabled: enabled, Severity: sev,
			Interval: r.Interval.String(), Window: r.Window.String(), Params: r.Params, Values: p, ExemptHosts: exempt,
			LastCount: st.lastCount, LastError: st.lastErr, LastMs: st.lastMs}
		if exempt == nil {
			info.ExemptHosts = []string{}
		}
		if !st.lastRun.IsZero() {
			t := st.lastRun
			info.LastRun = &t
		}
		out = append(out, info)
	}
	return out
}

// UpdateConfig validates and persists overrides for one rule.
func (e *Engine) UpdateConfig(ctx context.Context, name string, rc RuleConfig) error {
	r := e.rule(name)
	if r == nil {
		return fmt.Errorf("unknown rule %q", name)
	}
	if rc.Severity != "" && db.SeverityRank(rc.Severity) == 0 {
		return fmt.Errorf("invalid severity %q", rc.Severity)
	}
	for k := range rc.Params {
		known := false
		for _, d := range r.Params {
			if d.Name == k {
				known = true
			}
		}
		if !known {
			return fmt.Errorf("unknown parameter %q for rule %s", k, name)
		}
	}
	e.mu.Lock()
	e.cfg[name] = rc
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
	for _, r := range e.rules {
		e.mu.Lock()
		st := e.state[r.Name]
		due := st.lastRun.IsZero() || now.Sub(st.lastRun) >= r.Interval
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

// RunRule evaluates one rule now (force ignores the enabled flag; used by the API for testing)
// and returns the findings that were raised.
func (e *Engine) RunRule(ctx context.Context, name string, force bool) ([]db.Alert, error) {
	r := e.rule(name)
	if r == nil {
		return nil, fmt.Errorf("unknown rule %q", name)
	}
	enabled, severity, p, exempt := e.effective(r)
	e.mu.Lock()
	st := e.state[r.Name]
	st.lastRun = e.Now()
	e.mu.Unlock()
	if !enabled && !force {
		return nil, nil
	}
	start := time.Now()
	until := e.Now().UTC()
	w := db.Window{Since: until.Add(-r.Window), Until: until}
	findings, err := r.run(ctx, e, r, p, w)
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
	exemptSet, err := e.resolveExempt(ctx, exempt)
	if err != nil {
		return nil, err
	}
	var raised []db.Alert
	kept := 0
	for _, f := range findings {
		if exemptSet[f.Host] || exemptSet[f.Peer] {
			continue
		}
		kept++
		f.Rule = r.Name
		if f.Severity == "" {
			f.Severity = severity
		}
		a, err := e.DB.UpsertAlert(ctx, f)
		if err != nil {
			return nil, fmt.Errorf("upsert alert: %w", err)
		}
		if a.Inserted || a.NotifiedAt == nil || e.Now().Sub(*a.NotifiedAt) > e.Cfg.NotifyRenotifyAfter {
			raised = append(raised, *a)
		}
	}
	e.mu.Lock()
	st.lastCount = kept
	e.mu.Unlock()
	if len(raised) > 0 && e.Notifier != nil {
		e.Notifier.Notify(ctx, raised)
	}
	return raised, nil
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
	r := e.rule("ids")
	enabled, _, p, exempt := e.effective(r)
	if !enabled {
		return nil
	}
	if sev, ok := f.Details["suricata_severity"].(int); ok && sev > p.Int("min_suricata_severity") {
		return nil
	}
	set, err := e.resolveExempt(ctx, exempt)
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
