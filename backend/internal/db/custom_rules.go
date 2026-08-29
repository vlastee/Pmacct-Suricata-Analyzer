package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// CustomRule is a user-defined detection rule as stored in custom_rules.
type CustomRule struct {
	Name        string
	Title       string
	Description string
	Kind        string // "sql" | "builtin"
	Base        string // kind=builtin: name of the built-in rule whose detector is reused
	SQL         string // kind=sql
	Params      map[string]any
	Severity    string
	Interval    time.Duration
	Window      time.Duration
	Enabled     bool
	ExemptHosts []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

const customRuleCols = `name, title, description, kind, base, sql, params, severity, interval_s, window_s, enabled, exempt_hosts, created_at, updated_at`

func scanCustomRule(row pgx.Row) (*CustomRule, error) {
	var r CustomRule
	var iv, win int
	if err := row.Scan(&r.Name, &r.Title, &r.Description, &r.Kind, &r.Base, &r.SQL, &r.Params, &r.Severity, &iv, &win, &r.Enabled, &r.ExemptHosts, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	r.Interval, r.Window = time.Duration(iv)*time.Second, time.Duration(win)*time.Second
	if r.Params == nil {
		r.Params = map[string]any{}
	}
	if r.ExemptHosts == nil {
		r.ExemptHosts = []string{}
	}
	return &r, nil
}

// ListCustomRules returns all user-defined rules, oldest first.
func (d *DB) ListCustomRules(ctx context.Context) ([]*CustomRule, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+customRuleCols+` FROM custom_rules ORDER BY created_at, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CustomRule{}
	for rows.Next() {
		r, err := scanCustomRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertCustomRule inserts or fully replaces one rule by name.
func (d *DB) UpsertCustomRule(ctx context.Context, r *CustomRule) error {
	if r.Params == nil {
		r.Params = map[string]any{}
	}
	if r.ExemptHosts == nil {
		r.ExemptHosts = []string{}
	}
	_, err := d.Pool.Exec(ctx, `
INSERT INTO custom_rules (name, title, description, kind, base, sql, params, severity, interval_s, window_s, enabled, exempt_hosts)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (name) DO UPDATE SET title = EXCLUDED.title, description = EXCLUDED.description, kind = EXCLUDED.kind, base = EXCLUDED.base,
  sql = EXCLUDED.sql, params = EXCLUDED.params, severity = EXCLUDED.severity, interval_s = EXCLUDED.interval_s, window_s = EXCLUDED.window_s,
  enabled = EXCLUDED.enabled, exempt_hosts = EXCLUDED.exempt_hosts, updated_at = now()`,
		r.Name, r.Title, r.Description, r.Kind, r.Base, r.SQL, r.Params, r.Severity, int(r.Interval/time.Second), int(r.Window/time.Second), r.Enabled, r.ExemptHosts)
	return err
}

// DeleteCustomRule removes a rule; false if it did not exist. Its alerts are kept.
func (d *DB) DeleteCustomRule(ctx context.Context, name string) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM custom_rules WHERE name = $1`, name)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ---- SQL-defined rules ----

// RuleSQLTimeout bounds one custom-rule query; MaxRuleFindings caps what one run may raise.
const (
	RuleSQLTimeout  = 30 * time.Second
	MaxRuleFindings = 500
)

// ValidateRuleSQL accepts a single read-only SELECT (or WITH … SELECT). Execution additionally
// happens inside a READ ONLY transaction with a statement timeout, so this is a usability check
// (clear error up front), not the security boundary.
func ValidateRuleSQL(q string) error {
	t := strings.TrimSpace(q)
	if t == "" {
		return errors.New("sql is empty")
	}
	up := strings.ToUpper(t)
	if !strings.HasPrefix(up, "SELECT") && !strings.HasPrefix(up, "WITH") {
		return errors.New("sql must be a single SELECT (or WITH … SELECT) statement")
	}
	if strings.Contains(t, ";") {
		return errors.New("sql must not contain ';' (one statement only)")
	}
	return nil
}

// RunRuleSQL executes a user-defined query as a detection rule. The query receives
// $1 = window start, $2 = window end (timestamptz) and $3 = local networks (cidr[]), runs in a
// READ ONLY transaction under RuleSQLTimeout, and must return a host (or peer) column; optional
// columns: peer, port, title, severity, details (jsonb), key. At most MaxRuleFindings rows are used.
func (d *DB) RunRuleSQL(ctx context.Context, q string, w Window, locals []string) ([]Finding, error) {
	if err := ValidateRuleSQL(q); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, RuleSQLTimeout+5*time.Second)
	defer cancel()
	tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", RuleSQLTimeout.Milliseconds())); err != nil {
		return nil, err
	}
	// The wrapper references every parameter so a query that ignores some of them still binds,
	// and enforces the row cap server-side.
	wrapped := fmt.Sprintf(`WITH _rule_window AS (SELECT $1::timestamptz AS since, $2::timestamptz AS until, $3::cidr[] AS locals)
SELECT * FROM (%s) _rule_query LIMIT %d`, strings.TrimSpace(q), MaxRuleFindings+1)
	rows, err := tx.Query(ctx, wrapped, w.Since, w.Until, locals)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	idx := map[string]int{}
	for i, f := range rows.FieldDescriptions() {
		idx[strings.ToLower(f.Name)] = i
	}
	if _, ok := idx["host"]; !ok {
		if _, ok := idx["peer"]; !ok {
			return nil, errors.New("query must return a \"host\" (or \"peer\") column")
		}
	}
	var out []Finding
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		get := func(k string) any {
			if i, ok := idx[k]; ok {
				return vals[i]
			}
			return nil
		}
		f := Finding{Host: ipString(get("host")), Peer: ipString(get("peer")), Port: toInt(get("port")),
			Title: strings.TrimSpace(stringOf(get("title"))), Key: strings.TrimSpace(stringOf(get("key")))}
		if sev := strings.ToLower(strings.TrimSpace(stringOf(get("severity")))); SeverityRank(sev) > 0 {
			f.Severity = sev
		}
		if f.Host == "" && f.Peer == "" {
			continue
		}
		f.Details = detailsOf(get("details"))
		out = append(out, f)
		if len(out) >= MaxRuleFindings {
			return out, fmt.Errorf("query returned more than %d rows; aggregate or filter further", MaxRuleFindings)
		}
	}
	return out, rows.Err()
}

func stringOf(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	}
	return fmt.Sprint(v)
}

func ipString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case netip.Prefix:
		return x.Addr().Unmap().String()
	case netip.Addr:
		return x.Unmap().String()
	case string:
		s := strings.TrimSpace(x)
		if i := strings.IndexByte(s, '/'); i > 0 {
			s = s[:i]
		}
		if a, err := netip.ParseAddr(s); err == nil {
			return a.Unmap().String()
		}
		return s
	}
	return ipString(fmt.Sprint(v))
}

func toInt(v any) int {
	switch x := v.(type) {
	case nil:
		return 0
	case int:
		return x
	case int16:
		return int(x)
	case int32:
		return int(x)
	case int64:
		return int(x)
	case float32:
		return int(x)
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	}
	n, _ := strconv.Atoi(fmt.Sprint(v))
	return n
}

func detailsOf(v any) map[string]any {
	switch x := v.(type) {
	case nil:
		return map[string]any{}
	case map[string]any:
		return x
	case string:
		var m map[string]any
		if json.Unmarshal([]byte(x), &m) == nil && m != nil {
			return m
		}
		return map[string]any{"details": x}
	case []byte:
		return detailsOf(string(x))
	}
	return map[string]any{"details": fmt.Sprint(v)}
}
