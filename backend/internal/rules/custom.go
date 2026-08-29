package rules

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// CustomSpec is the API shape of a user-defined rule. Two kinds:
//
//   - "sql":     Logic is a SELECT the user writes (see db.RunRuleSQL for the contract).
//   - "builtin": Logic is a built-in rule's detector (Base) with this rule's own parameters,
//     severity, timing and exemptions — "duplicate a built-in and tune it differently".
type CustomSpec struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Kind        string         `json:"kind"`
	Base        string         `json:"base,omitempty"`
	SQL         string         `json:"sql,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
	Severity    string         `json:"severity"`
	Interval    string         `json:"interval"`
	Window      string         `json:"window"`
	Enabled     *bool          `json:"enabled,omitempty"`
	ExemptHosts []string       `json:"exempt_hosts,omitempty"`
}

var (
	customNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,39}$`)
	// Segments used by the rules API itself must never be rule names.
	reservedNames = map[string]bool{"custom": true, "preview": true, "run": true}
)

// toRow validates a spec and turns it into a storable row.
func (e *Engine) toRow(spec CustomSpec) (*db.CustomRule, error) {
	name := strings.TrimSpace(spec.Name)
	if !customNameRe.MatchString(name) {
		return nil, invalid("name must be 2-40 chars of a-z, 0-9 and _, starting with a letter")
	}
	if reservedNames[name] {
		return nil, invalid("name %q is reserved", name)
	}
	row := &db.CustomRule{Name: name, Title: strings.TrimSpace(spec.Title), Description: strings.TrimSpace(spec.Description),
		Kind: strings.TrimSpace(spec.Kind), Params: spec.Params, Severity: strings.ToLower(strings.TrimSpace(spec.Severity)),
		Enabled: true, ExemptHosts: []string{}}
	if row.Title == "" {
		row.Title = name
	}
	if row.Params == nil {
		row.Params = map[string]any{}
	}
	if row.Severity == "" {
		row.Severity = db.SevWarning
	}
	if db.SeverityRank(row.Severity) == 0 {
		return nil, invalid("invalid severity %q", spec.Severity)
	}
	if spec.Enabled != nil {
		row.Enabled = *spec.Enabled
	}
	for _, h := range spec.ExemptHosts {
		if h = strings.TrimSpace(h); h != "" {
			row.ExemptHosts = append(row.ExemptHosts, h)
		}
	}
	defInterval, defWindow := time.Minute, 10*time.Minute
	switch row.Kind {
	case "sql":
		row.SQL = strings.TrimSpace(spec.SQL)
		if err := db.ValidateRuleSQL(row.SQL); err != nil {
			return nil, invalid("%s", err.Error())
		}
		if len(row.Params) > 0 {
			return nil, invalid("sql rules take no parameters (put values in the query)")
		}
	case "builtin":
		row.Base = strings.TrimSpace(spec.Base)
		base := e.builtinRule(row.Base)
		if base == nil || row.Base == "ids" {
			return nil, invalid("base must be the name of a built-in detection rule (not %q)", row.Base)
		}
		for k := range row.Params {
			known := false
			for _, d := range base.Params {
				if d.Name == k {
					known = true
				}
			}
			if !known {
				return nil, invalid("unknown parameter %q for base rule %s", k, row.Base)
			}
		}
		defInterval, defWindow = base.Interval, base.Window
	default:
		return nil, invalid("kind must be \"sql\" or \"builtin\"")
	}
	iv, err := parseTiming("interval", spec.Interval, MinInterval, MaxInterval)
	if err != nil {
		return nil, err
	}
	win, err := parseTiming("window", spec.Window, MinWindow, MaxWindow)
	if err != nil {
		return nil, err
	}
	row.Interval, row.Window = iv, win
	if row.Interval == 0 {
		row.Interval = defInterval
	}
	if row.Window == 0 {
		row.Window = defWindow
	}
	return row, nil
}

// buildCustom turns a stored row into an executable rule.
func (e *Engine) buildCustom(row *db.CustomRule) (*Rule, error) {
	r := &Rule{Name: row.Name, Title: row.Title, Description: row.Description, Severity: row.Severity,
		Interval: row.Interval, Window: row.Window, custom: row}
	switch row.Kind {
	case "sql":
		r.run = func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
			return e.DB.RunRuleSQL(ctx, r.custom.SQL, w, e.Cfg.LocalNetworksCIDR())
		}
	case "builtin":
		base := e.builtinRule(row.Base)
		if base == nil {
			return nil, fmt.Errorf("custom rule %s: base rule %q no longer exists", row.Name, row.Base)
		}
		r.base, r.Params = base, base.Params
		r.run = func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
			return base.run(ctx, e, base, p, w)
		}
	default:
		return nil, fmt.Errorf("custom rule %s: unknown kind %q", row.Name, row.Kind)
	}
	return r, nil
}

// loadCustom (re)builds the custom rule list from the database. A rule that cannot be built
// (e.g. its base rule was removed) is skipped with a log line rather than blocking startup.
func (e *Engine) loadCustom(ctx context.Context) error {
	rows, err := e.DB.ListCustomRules(ctx)
	if err != nil {
		return err
	}
	var list []*Rule
	for _, row := range rows {
		r, err := e.buildCustom(row)
		if err != nil {
			e.warn(err)
			continue
		}
		list = append(list, r)
	}
	e.mu.Lock()
	e.custom = list
	for _, r := range list {
		if e.state[r.Name] == nil {
			e.state[r.Name] = &ruleState{}
		}
	}
	e.mu.Unlock()
	return nil
}

func (e *Engine) warn(err error) { logWarn("custom rule", err) }

// install replaces (or adds) one custom rule in the live list.
func (e *Engine) install(r *Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	replaced := false
	for i, c := range e.custom {
		if c.Name == r.Name {
			e.custom[i] = r
			replaced = true
		}
	}
	if !replaced {
		e.custom = append(e.custom, r)
	}
	if e.state[r.Name] == nil {
		e.state[r.Name] = &ruleState{}
	}
}

// SaveCustom creates (create=true) or replaces a custom rule and returns its API view.
func (e *Engine) SaveCustom(ctx context.Context, spec CustomSpec, create bool) (RuleInfo, error) {
	row, err := e.toRow(spec)
	if err != nil {
		return RuleInfo{}, err
	}
	existing := e.rule(row.Name)
	if create && existing != nil {
		return RuleInfo{}, invalid("a rule named %q already exists", row.Name)
	}
	if !create {
		if existing == nil || existing.custom == nil {
			return RuleInfo{}, unknownRule(row.Name)
		}
	}
	r, err := e.buildCustom(row)
	if err != nil {
		return RuleInfo{}, invalid("%s", err.Error())
	}
	if err := e.DB.UpsertCustomRule(ctx, row); err != nil {
		return RuleInfo{}, err
	}
	e.install(r)
	return e.info(r), nil
}

// updateCustomConfig applies a RuleConfig-style partial update to a custom rule's row.
func (e *Engine) updateCustomConfig(ctx context.Context, r *Rule, rc RuleConfig) error {
	row := *r.custom
	if rc.Enabled != nil {
		row.Enabled = *rc.Enabled
	}
	if rc.Severity != "" {
		row.Severity = rc.Severity
	}
	if rc.Params != nil {
		row.Params = rc.Params
	}
	if rc.ExemptHosts != nil {
		row.ExemptHosts = rc.ExemptHosts
	}
	if d, _ := parseTiming("interval", rc.Interval, MinInterval, MaxInterval); d > 0 {
		row.Interval = d
	}
	if d, _ := parseTiming("window", rc.Window, MinWindow, MaxWindow); d > 0 {
		row.Window = d
	}
	nr, err := e.buildCustom(&row)
	if err != nil {
		return err
	}
	if err := e.DB.UpsertCustomRule(ctx, &row); err != nil {
		return err
	}
	e.install(nr)
	return nil
}

// DeleteCustom removes a custom rule. Alerts it raised are kept (they still name the rule).
func (e *Engine) DeleteCustom(ctx context.Context, name string) error {
	r := e.rule(name)
	if r == nil || r.custom == nil {
		return unknownRule(name)
	}
	if _, err := e.DB.DeleteCustomRule(ctx, name); err != nil {
		return err
	}
	e.mu.Lock()
	for i, c := range e.custom {
		if c.Name == name {
			e.custom = append(e.custom[:i], e.custom[i+1:]...)
			break
		}
	}
	delete(e.state, name)
	e.mu.Unlock()
	return nil
}

// PreviewSpec evaluates an unsaved rule definition and returns what it would raise right now.
func (e *Engine) PreviewSpec(ctx context.Context, spec CustomSpec) ([]db.Finding, error) {
	if strings.TrimSpace(spec.Name) == "" {
		spec.Name = "preview_rule"
	}
	row, err := e.toRow(spec)
	if err != nil {
		return nil, err
	}
	r, err := e.buildCustom(row)
	if err != nil {
		return nil, invalid("%s", err.Error())
	}
	findings, _, err := e.evaluate(ctx, r)
	if err != nil {
		var ve *ValidationError
		if !errors.As(err, &ve) {
			err = invalid("%s", err.Error()) // query errors are the user's to fix, not server faults
		}
		return nil, err
	}
	if findings == nil {
		findings = []db.Finding{}
	}
	return findings, nil
}
