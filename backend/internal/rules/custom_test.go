package rules

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

func testEngine() *Engine {
	return &Engine{builtin: builtinRules(), cfg: Config{}, state: map[string]*ruleState{}, Now: time.Now}
}

func isInvalid(t *testing.T, err error, want string) {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected a ValidationError containing %q, got %v", want, err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q should mention %q", err.Error(), want)
	}
}

func TestCustomSpecSQL(t *testing.T) {
	e := testEngine()
	row, err := e.toRow(CustomSpec{Name: "big_upload", Kind: "sql", SQL: "SELECT ip_src AS host FROM acct"})
	if err != nil {
		t.Fatal(err)
	}
	if row.Title != "big_upload" || row.Severity != db.SevWarning || !row.Enabled || row.Interval != time.Minute || row.Window != 10*time.Minute {
		t.Errorf("defaults: %+v", row)
	}
	r, err := e.buildCustom(row)
	if err != nil {
		t.Fatal(err)
	}
	ef := e.effective(r)
	if ef.interval != time.Minute || ef.window != 10*time.Minute || ef.severity != db.SevWarning || !ef.enabled {
		t.Errorf("effective: %+v", ef)
	}

	_, err = e.toRow(CustomSpec{Name: "Bad-Name", Kind: "sql", SQL: "SELECT 1"})
	isInvalid(t, err, "name must be")
	_, err = e.toRow(CustomSpec{Name: "custom", Kind: "sql", SQL: "SELECT 1"})
	isInvalid(t, err, "reserved")
	_, err = e.toRow(CustomSpec{Name: "x_rule", Kind: "sql", SQL: "DELETE FROM acct"})
	isInvalid(t, err, "SELECT")
	_, err = e.toRow(CustomSpec{Name: "x_rule", Kind: "sql", SQL: "SELECT 1; DROP TABLE acct"})
	isInvalid(t, err, "';'")
	_, err = e.toRow(CustomSpec{Name: "x_rule", Kind: "sql", SQL: "SELECT 1", Params: map[string]any{"a": 1}})
	isInvalid(t, err, "no parameters")
	_, err = e.toRow(CustomSpec{Name: "x_rule", Kind: "sql", SQL: "SELECT 1", Severity: "urgent"})
	isInvalid(t, err, "severity")
	_, err = e.toRow(CustomSpec{Name: "x_rule", Kind: "sql", SQL: "SELECT 1", Interval: "10s"})
	isInvalid(t, err, "interval must be between")
	_, err = e.toRow(CustomSpec{Name: "x_rule", Kind: "sql", SQL: "SELECT 1", Window: "60d"})
	isInvalid(t, err, "window")
	_, err = e.toRow(CustomSpec{Name: "x_rule", Kind: "yaml"})
	isInvalid(t, err, "kind")
}

func TestCustomSpecBuiltin(t *testing.T) {
	e := testEngine()
	spec := CustomSpec{Name: "ports_strict", Kind: "builtin", Base: "suspicious_port", Severity: "critical", Interval: "5m",
		Params: map[string]any{"ports": []any{443.0, 8443.0}}, ExemptHosts: []string{" 10.0.0.1 ", ""}}
	row, err := e.toRow(spec)
	if err != nil {
		t.Fatal(err)
	}
	if row.Interval != 5*time.Minute || row.Window != 10*time.Minute || len(row.ExemptHosts) != 1 || row.ExemptHosts[0] != "10.0.0.1" {
		t.Errorf("row: %+v", row)
	}
	r, err := e.buildCustom(row)
	if err != nil {
		t.Fatal(err)
	}
	ef := e.effective(r)
	if len(ef.params.Ints("ports")) != 2 || len(ef.params.Ints("critical_ports")) == 0 {
		t.Errorf("params should merge over the base defaults: %+v", ef.params)
	}
	if len(r.Params) != 2 || ef.severity != db.SevCritical {
		t.Errorf("rule: params=%d severity=%s", len(r.Params), ef.severity)
	}

	_, err = e.toRow(CustomSpec{Name: "x_rule", Kind: "builtin", Base: "ids"})
	isInvalid(t, err, "base must be")
	_, err = e.toRow(CustomSpec{Name: "x_rule", Kind: "builtin", Base: "nope"})
	isInvalid(t, err, "base must be")
	_, err = e.toRow(CustomSpec{Name: "x_rule", Kind: "builtin", Base: "port_scan", Params: map[string]any{"bogus": 1}})
	isInvalid(t, err, "unknown parameter")
}

func TestValidateConfigTiming(t *testing.T) {
	e := testEngine()
	r := e.builtinRule("port_scan")
	if err := validateConfig(r, RuleConfig{Interval: "2m", Window: "1h", Severity: "info"}); err != nil {
		t.Fatal(err)
	}
	isInvalid(t, validateConfig(r, RuleConfig{Interval: "soon"}), "interval")
	isInvalid(t, validateConfig(r, RuleConfig{Window: "10s"}), "window must be between")
	isInvalid(t, validateConfig(r, RuleConfig{Params: map[string]any{"nope": 1}}), "unknown parameter")
	isInvalid(t, validateConfig(r, RuleConfig{Severity: "meh"}), "severity")
}

func TestDefaultTitle(t *testing.T) {
	r := &Rule{Title: "Watchlist hit"}
	if got := defaultTitle(r, db.Finding{Host: "10.0.0.5", Peer: "1.2.3.4", Port: 443}); got != "Watchlist hit: 10.0.0.5 → 1.2.3.4:443" {
		t.Errorf("title: %q", got)
	}
	if got := defaultTitle(r, db.Finding{Peer: "1.2.3.4"}); got != "Watchlist hit: 1.2.3.4" {
		t.Errorf("title: %q", got)
	}
}

func TestPreviewSpecRejectsBadSpec(t *testing.T) {
	e := testEngine()
	_, err := e.PreviewSpec(t.Context(), CustomSpec{Kind: "sql", SQL: "UPDATE acct SET bytes = 0"})
	isInvalid(t, err, "SELECT")
}
