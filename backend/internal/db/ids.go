package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// IDSEvent is a Suricata alert.
type IDSEvent struct {
	ID        int64           `json:"id"`
	TS        time.Time       `json:"ts"`
	SrcIP     *string         `json:"src_ip"`
	SrcPort   *int            `json:"src_port"`
	DstIP     *string         `json:"dst_ip"`
	DstPort   *int            `json:"dst_port"`
	Proto     *string         `json:"proto"`
	SID       *int64          `json:"sid"`
	Signature *string         `json:"signature"`
	Category  *string         `json:"category"`
	Severity  *int            `json:"severity"`
	Action    *string         `json:"action"`
	AppProto  *string         `json:"app_proto"`
	Raw       json.RawMessage `json:"raw,omitempty"`
	SrcName   *string         `json:"src_nickname"`
	DstName   *string         `json:"dst_nickname"`
}

// InsertIDSEvent stores one alert event.
func (d *DB) InsertIDSEvent(ctx context.Context, e *IDSEvent) error {
	_, err := d.Pool.Exec(ctx, `INSERT INTO ids_events (ts, src_ip, src_port, dst_ip, dst_port, proto, sid, signature, category, severity, action, app_proto, raw)
VALUES ($1, $2::inet, $3, $4::inet, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		e.TS, e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Proto, e.SID, e.Signature, e.Category, e.Severity, e.Action, e.AppProto, e.Raw)
	return err
}

// IDSOptions filters ListIDSEvents.
type IDSOptions struct {
	Since  time.Time
	IP     string
	SID    int64
	Limit  int
	Offset int
	Raw    bool
}

// ListIDSEvents returns recent IDS events.
func (d *DB) ListIDSEvents(ctx context.Context, o IDSOptions) ([]IDSEvent, error) {
	if o.Limit <= 0 || o.Limit > 1000 {
		o.Limit = 200
	}
	args := []any{o.Since}
	conds := []string{"e.ts >= $1"}
	if o.IP != "" {
		args = append(args, o.IP)
		conds = append(conds, fmt.Sprintf("(e.src_ip = $%d::inet OR e.dst_ip = $%d::inet)", len(args), len(args)))
	}
	if o.SID > 0 {
		args = append(args, o.SID)
		conds = append(conds, fmt.Sprintf("e.sid = $%d", len(args)))
	}
	raw := "NULL::jsonb"
	if o.Raw {
		raw = "e.raw"
	}
	args = append(args, o.Limit, o.Offset)
	rows, err := d.Pool.Query(ctx, `SELECT e.id, e.ts, host(e.src_ip), e.src_port, host(e.dst_ip), e.dst_port, e.proto, e.sid, e.signature, e.category, e.severity, e.action, e.app_proto, `+raw+`, ns.nickname, nd.nickname
FROM ids_events e LEFT JOIN ip_nicknames ns ON ns.ip = e.src_ip LEFT JOIN ip_nicknames nd ON nd.ip = e.dst_ip
WHERE `+strings.Join(conds, " AND ")+fmt.Sprintf(` ORDER BY e.ts DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IDSEvent{}
	for rows.Next() {
		var e IDSEvent
		if err := rows.Scan(&e.ID, &e.TS, &e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.Proto, &e.SID, &e.Signature, &e.Category, &e.Severity, &e.Action, &e.AppProto, &e.Raw, &e.SrcName, &e.DstName); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// IDSSignatureStat aggregates events by signature.
type IDSSignatureStat struct {
	SID       int64     `json:"sid"`
	Signature string    `json:"signature"`
	Category  *string   `json:"category"`
	Severity  *int      `json:"severity"`
	Count     int64     `json:"count"`
	Sources   int64     `json:"sources"`
	LastSeen  time.Time `json:"last_seen"`
}

// IDSSummary returns per-signature counts since a time.
func (d *DB) IDSSummary(ctx context.Context, since time.Time, limit int) ([]IDSSignatureStat, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	var total int64
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ids_events WHERE ts >= $1`, since).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.Pool.Query(ctx, `SELECT COALESCE(sid,0), COALESCE(signature,'?'), MIN(category), MIN(severity), COUNT(*), COUNT(DISTINCT src_ip), MAX(ts)
FROM ids_events WHERE ts >= $1 GROUP BY 1,2 ORDER BY 5 DESC LIMIT $2`, since, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []IDSSignatureStat{}
	for rows.Next() {
		var s IDSSignatureStat
		if err := rows.Scan(&s.SID, &s.Signature, &s.Category, &s.Severity, &s.Count, &s.Sources, &s.LastSeen); err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}

// ---- names ----

// UpsertIPName records a name observed for an IP.
func (d *DB) UpsertIPName(ctx context.Context, ip, name, source string) error {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || len(name) > 253 {
		return nil
	}
	_, err := d.Pool.Exec(ctx, `INSERT INTO ip_names (ip, name, source) VALUES ($1::inet, $2, $3)
ON CONFLICT (ip, name) DO UPDATE SET last_seen = now(), hits = ip_names.hits + 1, source = EXCLUDED.source`, ip, name, source)
	return err
}

// IPName is an observed name.
type IPName struct {
	Name     string    `json:"name"`
	Source   string    `json:"source"`
	Hits     int       `json:"hits"`
	LastSeen time.Time `json:"last_seen"`
}

// IPNames lists names for an IP, most recent first.
func (d *DB) IPNames(ctx context.Context, ip string, limit int) ([]IPName, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := d.Pool.Query(ctx, `SELECT name, source, hits, last_seen FROM ip_names WHERE ip = $1::inet ORDER BY last_seen DESC LIMIT $2`, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPName{}
	for rows.Next() {
		var n IPName
		if err := rows.Scan(&n.Name, &n.Source, &n.Hits, &n.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// namesSubquery yields up to 3 recent names for the ip column expression.
func namesSubquery(ipExpr string) string {
	return `(SELECT array_agg(name ORDER BY last_seen DESC) FROM (SELECT name, last_seen FROM ip_names WHERE ip_names.ip = ` + ipExpr + ` ORDER BY last_seen DESC LIMIT 3) n)`
}
