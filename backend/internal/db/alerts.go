package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Severity levels, ordered.
const (
	SevInfo     = "info"
	SevWarning  = "warning"
	SevCritical = "critical"
)

// SeverityRank orders severities for comparisons.
func SeverityRank(s string) int {
	switch s {
	case SevCritical:
		return 3
	case SevWarning:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

// Alert is a deduplicated finding.
type Alert struct {
	ID         int64           `json:"id"`
	Rule       string          `json:"rule"`
	Severity   string          `json:"severity"`
	Host       *string         `json:"host"`
	HostName   *string         `json:"host_nickname"`
	Peer       *string         `json:"peer"`
	PeerName   *string         `json:"peer_nickname"`
	Port       *int            `json:"port"`
	Title      string          `json:"title"`
	Details    json.RawMessage `json:"details"`
	Count      int             `json:"count"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
	State      string          `json:"state"`
	AckedAt    *time.Time      `json:"acked_at"`
	ResolvedAt *time.Time      `json:"resolved_at"`
	NotifiedAt *time.Time      `json:"notified_at"`
	DedupeKey  string          `json:"-"`
	Inserted   bool            `json:"-"` // set by UpsertAlert: true when newly created
	// Computed by the API for list views: the trusted-list pattern covering host / peer, if any.
	HostExcluded string `json:"host_excluded,omitempty"`
	PeerExcluded string `json:"peer_excluded,omitempty"`
}

// Finding is what a rule produces; the engine turns it into an Alert.
type Finding struct {
	Rule     string         `json:"rule"`
	Severity string         `json:"severity"`
	Host     string         `json:"host,omitempty"` // may be ""
	Peer     string         `json:"peer,omitempty"` // may be ""
	Port     int            `json:"port,omitempty"`
	Title    string         `json:"title"`
	Details  map[string]any `json:"details"`
	Key      string         `json:"key,omitempty"` // extra dedupe discriminator (e.g. signature id)
}

// DedupeKey builds the identity of a finding.
func (f Finding) DedupeKey() string {
	parts := []string{f.Rule, f.Host, f.Peer}
	if f.Port > 0 {
		parts = append(parts, fmt.Sprint(f.Port))
	}
	if f.Key != "" {
		parts = append(parts, f.Key)
	}
	return strings.Join(parts, "|")
}

// UpsertAlert inserts a finding or bumps the matching open alert. Returns the alert with
// Inserted=true when it was newly created. Severity only escalates.
func (d *DB) UpsertAlert(ctx context.Context, f Finding) (*Alert, error) {
	details, _ := json.Marshal(f.Details)
	if f.Details == nil {
		details = []byte("{}")
	}
	var host, peer *string
	if f.Host != "" {
		host = &f.Host
	}
	if f.Peer != "" {
		peer = &f.Peer
	}
	var port *int
	if f.Port > 0 {
		port = &f.Port
	}
	var a Alert
	var hostS, peerS *string
	err := d.Pool.QueryRow(ctx, `
INSERT INTO alerts (rule, severity, host, peer, port, title, details, dedupe_key)
VALUES ($1, $2, $3::inet, $4::inet, $5, $6, $7, $8)
ON CONFLICT (dedupe_key) WHERE state <> 'resolved' DO UPDATE SET
  count = alerts.count + 1, last_seen = now(), title = EXCLUDED.title, details = EXCLUDED.details,
  severity = CASE WHEN EXCLUDED.severity = 'critical' OR (EXCLUDED.severity = 'warning' AND alerts.severity = 'info') THEN EXCLUDED.severity ELSE alerts.severity END
RETURNING id, rule, severity, host(host), host(peer), port, title, details, count, first_seen, last_seen, state, acked_at, resolved_at, notified_at, dedupe_key, (xmax = 0)`,
		f.Rule, f.Severity, host, peer, port, f.Title, details, f.DedupeKey()).Scan(
		&a.ID, &a.Rule, &a.Severity, &hostS, &peerS, &a.Port, &a.Title, &a.Details, &a.Count, &a.FirstSeen, &a.LastSeen,
		&a.State, &a.AckedAt, &a.ResolvedAt, &a.NotifiedAt, &a.DedupeKey, &a.Inserted)
	if err != nil {
		return nil, err
	}
	a.Host, a.Peer = hostS, peerS
	return &a, nil
}

// AlertsOptions filters ListAlerts.
type AlertsOptions struct {
	State    string // open | acked | resolved | active (open+acked) | "" (all)
	Severity string
	Rule     string
	Host     string
	Since    time.Time
	Limit    int
	Offset   int
}

const alertCols = `a.id, a.rule, a.severity, host(a.host), nh.nickname, host(a.peer), np.nickname, a.port, a.title, a.details, a.count,
  a.first_seen, a.last_seen, a.state, a.acked_at, a.resolved_at, a.notified_at, a.dedupe_key`

func scanAlert(rows pgx.Rows) (*Alert, error) {
	var a Alert
	if err := rows.Scan(&a.ID, &a.Rule, &a.Severity, &a.Host, &a.HostName, &a.Peer, &a.PeerName, &a.Port, &a.Title, &a.Details, &a.Count,
		&a.FirstSeen, &a.LastSeen, &a.State, &a.AckedAt, &a.ResolvedAt, &a.NotifiedAt, &a.DedupeKey); err != nil {
		return nil, err
	}
	return &a, nil
}

// ListAlerts returns alerts newest-activity first.
func (d *DB) ListAlerts(ctx context.Context, o AlertsOptions) ([]Alert, int64, error) {
	if o.Limit <= 0 || o.Limit > 1000 {
		o.Limit = 100
	}
	args := []any{}
	conds := []string{"TRUE"}
	switch o.State {
	case "active":
		conds = append(conds, "a.state <> 'resolved'")
	case "":
	default:
		args = append(args, o.State)
		conds = append(conds, fmt.Sprintf("a.state = $%d", len(args)))
	}
	if o.Severity != "" {
		args = append(args, o.Severity)
		conds = append(conds, fmt.Sprintf("a.severity = $%d", len(args)))
	}
	if o.Rule != "" {
		args = append(args, o.Rule)
		conds = append(conds, fmt.Sprintf("a.rule = $%d", len(args)))
	}
	if o.Host != "" {
		args = append(args, o.Host)
		conds = append(conds, fmt.Sprintf("(a.host = $%d::inet OR a.peer = $%d::inet)", len(args), len(args)))
	}
	if !o.Since.IsZero() {
		args = append(args, o.Since)
		conds = append(conds, fmt.Sprintf("a.last_seen >= $%d", len(args)))
	}
	where := strings.Join(conds, " AND ")
	var total int64
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts a WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, o.Limit, o.Offset)
	rows, err := d.Pool.Query(ctx, `SELECT `+alertCols+` FROM alerts a
LEFT JOIN ip_nicknames nh ON nh.ip = a.host LEFT JOIN ip_nicknames np ON np.ip = a.peer
WHERE `+where+fmt.Sprintf(` ORDER BY a.last_seen DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *a)
	}
	return out, total, rows.Err()
}

// GetAlert fetches one alert.
func (d *DB) GetAlert(ctx context.Context, id int64) (*Alert, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+alertCols+` FROM alerts a
LEFT JOIN ip_nicknames nh ON nh.ip = a.host LEFT JOIN ip_nicknames np ON np.ip = a.peer WHERE a.id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanAlert(rows)
}

// SetAlertState transitions an alert (open -> acked/resolved, acked -> open/resolved).
func (d *DB) SetAlertState(ctx context.Context, id int64, state string) (bool, error) {
	var q string
	switch state {
	case "acked":
		q = `UPDATE alerts SET state='acked', acked_at=now() WHERE id=$1 AND state <> 'resolved'`
	case "resolved":
		q = `UPDATE alerts SET state='resolved', resolved_at=now() WHERE id=$1 AND state <> 'resolved'`
	case "open":
		q = `UPDATE alerts SET state='open', acked_at=NULL WHERE id=$1 AND state = 'acked'`
	default:
		return false, fmt.Errorf("invalid state %q", state)
	}
	tag, err := d.Pool.Exec(ctx, q, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ReopenAlert moves a resolved alert back to open. Refused (ok=false, conflict=id) when another
// live alert already carries the same dedupe key — the open one is the current case.
func (d *DB) ReopenAlert(ctx context.Context, id int64) (ok bool, conflict int64, err error) {
	tag, err := d.Pool.Exec(ctx, `UPDATE alerts a SET state='open', acked_at=NULL, resolved_at=NULL, reopened_at=now()
WHERE a.id=$1 AND a.state='resolved'
  AND NOT EXISTS (SELECT 1 FROM alerts b WHERE b.dedupe_key=a.dedupe_key AND b.id<>a.id AND b.state<>'resolved')`, id)
	if err != nil {
		return false, 0, err
	}
	if tag.RowsAffected() > 0 {
		return true, 0, nil
	}
	err = d.Pool.QueryRow(ctx, `SELECT b.id FROM alerts a JOIN alerts b ON b.dedupe_key=a.dedupe_key AND b.id<>a.id AND b.state<>'resolved'
WHERE a.id=$1 ORDER BY b.id DESC LIMIT 1`, id).Scan(&conflict)
	if err == pgx.ErrNoRows {
		return false, 0, nil
	}
	return false, conflict, err
}

// ResolveAlerts resolves all active alerts matching a rule/host filter (bulk actions from the UI).
func (d *DB) ResolveAlerts(ctx context.Context, rule, host string) (int64, error) {
	args := []any{}
	conds := []string{"state <> 'resolved'"}
	if rule != "" {
		args = append(args, rule)
		conds = append(conds, fmt.Sprintf("rule = $%d", len(args)))
	}
	if host != "" {
		args = append(args, host)
		conds = append(conds, fmt.Sprintf("(host = $%d::inet OR peer = $%d::inet)", len(args), len(args)))
	}
	tag, err := d.Pool.Exec(ctx, `UPDATE alerts SET state='resolved', resolved_at=now() WHERE `+strings.Join(conds, " AND "), args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// AutoResolveStale resolves open alerts not seen for the given duration.
func (d *DB) AutoResolveStale(ctx context.Context, after time.Duration) (int64, error) {
	tag, err := d.Pool.Exec(ctx, `UPDATE alerts SET state='resolved', resolved_at=now()
WHERE state <> 'resolved' AND GREATEST(last_seen, COALESCE(reopened_at, last_seen)) < now() - $1::interval`, after.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// MarkNotified records that an alert was sent.
func (d *DB) MarkNotified(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := d.Pool.Exec(ctx, `UPDATE alerts SET notified_at = now() WHERE id = ANY($1)`, ids)
	return err
}

// AlertSummary counts active alerts by severity and rule.
type AlertSummary struct {
	Open     int64            `json:"open"`
	Acked    int64            `json:"acked"`
	Critical int64            `json:"critical"`
	Warning  int64            `json:"warning"`
	Info     int64            `json:"info"`
	ByRule   map[string]int64 `json:"by_rule"`
	Last24h  int64            `json:"last_24h"`
}

// AlertSummary returns counts for the nav badge and dashboard.
func (d *DB) AlertSummary(ctx context.Context) (*AlertSummary, error) {
	s := AlertSummary{ByRule: map[string]int64{}}
	err := d.Pool.QueryRow(ctx, `SELECT
  COUNT(*) FILTER (WHERE state='open'), COUNT(*) FILTER (WHERE state='acked'),
  COUNT(*) FILTER (WHERE state<>'resolved' AND severity='critical'),
  COUNT(*) FILTER (WHERE state<>'resolved' AND severity='warning'),
  COUNT(*) FILTER (WHERE state<>'resolved' AND severity='info'),
  COUNT(*) FILTER (WHERE last_seen > now() - interval '24 hours')
FROM alerts`).Scan(&s.Open, &s.Acked, &s.Critical, &s.Warning, &s.Info, &s.Last24h)
	if err != nil {
		return nil, err
	}
	rows, err := d.Pool.Query(ctx, `SELECT rule, COUNT(*) FROM alerts WHERE state <> 'resolved' GROUP BY rule`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r string
		var n int64
		if err := rows.Scan(&r, &n); err != nil {
			return nil, err
		}
		s.ByRule[r] = n
	}
	return &s, rows.Err()
}

// HostRisk is a per-host risk score computed from active alerts.
type HostRisk struct {
	Score    int   `json:"score"`
	Critical int64 `json:"critical"`
	Warning  int64 `json:"warning"`
	Info     int64 `json:"info"`
}

// HostRisks returns risk scores keyed by host IP for all hosts with active alerts.
func (d *DB) HostRisks(ctx context.Context) (map[string]HostRisk, error) {
	rows, err := d.Pool.Query(ctx, `
SELECT host(ip), SUM(CASE severity WHEN 'critical' THEN 10 WHEN 'warning' THEN 3 ELSE 1 END)::int,
       COUNT(*) FILTER (WHERE severity='critical'), COUNT(*) FILTER (WHERE severity='warning'), COUNT(*) FILTER (WHERE severity='info')
FROM (SELECT host AS ip, severity FROM alerts WHERE state <> 'resolved' AND host IS NOT NULL
      UNION ALL SELECT peer, severity FROM alerts WHERE state <> 'resolved' AND peer IS NOT NULL) x
GROUP BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]HostRisk{}
	for rows.Next() {
		var ip string
		var r HostRisk
		if err := rows.Scan(&ip, &r.Score, &r.Critical, &r.Warning, &r.Info); err != nil {
			return nil, err
		}
		out[ip] = r
	}
	return out, rows.Err()
}

// ---- settings ----

// GetSetting loads a JSON setting into v; returns false when absent.
func (d *DB) GetSetting(ctx context.Context, key string, v any) (bool, error) {
	var raw []byte
	err := d.Pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&raw)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, v)
}

// SetSetting stores a JSON setting.
func (d *DB) SetSetting(ctx context.Context, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = d.Pool.Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, key, raw)
	return err
}
