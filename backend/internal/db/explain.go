package db

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ProgramKey identifies one program on one machine (by agent) or one local address.
type ProgramKey struct {
	AgentID   int64
	Host      string
	Exe       string
	User      string
	Container string
}

func (k ProgramKey) conds(args *[]any) string {
	var c []string
	if k.AgentID > 0 {
		*args = append(*args, k.AgentID)
		c = append(c, fmt.Sprintf("agent_id = $%d", len(*args)))
	} else {
		*args = append(*args, k.Host)
		c = append(c, fmt.Sprintf("host = $%d::inet", len(*args)))
	}
	*args = append(*args, k.Exe, k.User, k.Container)
	c = append(c, fmt.Sprintf("exe = $%d", len(*args)-2), fmt.Sprintf(`"user" = $%d`, len(*args)-1), fmt.Sprintf("container = $%d", len(*args)))
	return strings.Join(c, " AND ")
}

// ProgramSummary describes one program's reporting history.
type ProgramSummary struct {
	Rows          int64
	Conns         int64
	FirstInWindow *time.Time
	LastInWindow  *time.Time
	FirstEver     *time.Time
	LastEver      *time.Time
	Hashes        []string
	Names         []string
	Hosts         []string
	Agents        int64
	Pids          []int
	Cmdline       string
}

func (d *DB) ProgramSummaryFor(ctx context.Context, k ProgramKey, w Window) (*ProgramSummary, error) {
	var args []any
	cond := k.conds(&args)
	args = append(args, w.Since, w.Until)
	s := &ProgramSummary{Hashes: []string{}, Names: []string{}, Hosts: []string{}, Pids: []int{}}
	err := d.Pool.QueryRow(ctx, fmt.Sprintf(`
SELECT COUNT(*), COALESCE(SUM(count), 0), MIN(minute), MAX(minute),
       ARRAY(SELECT DISTINCT sha256 FROM endpoint_conns WHERE %[1]s AND minute >= $%[2]d AND minute < $%[3]d AND sha256 <> ''),
       ARRAY(SELECT DISTINCT name FROM endpoint_conns WHERE %[1]s AND name <> ''),
       ARRAY(SELECT DISTINCT host(host) FROM endpoint_conns WHERE %[1]s),
       (SELECT COUNT(DISTINCT agent_id) FROM endpoint_conns WHERE %[1]s),
       ARRAY(SELECT DISTINCT pid FROM endpoint_conns WHERE %[1]s AND minute >= $%[2]d AND minute < $%[3]d AND pid > 0 LIMIT 5),
       COALESCE((SELECT cmdline FROM endpoint_conns WHERE %[1]s AND cmdline <> '' ORDER BY minute DESC LIMIT 1), ''),
       (SELECT MIN(minute) FROM endpoint_conns WHERE %[1]s), (SELECT MAX(minute) FROM endpoint_conns WHERE %[1]s)
FROM endpoint_conns WHERE %[1]s AND minute >= $%[2]d AND minute < $%[3]d`, cond, len(args)-1, len(args)), args...).
		Scan(&s.Rows, &s.Conns, &s.FirstInWindow, &s.LastInWindow, &s.Hashes, &s.Names, &s.Hosts, &s.Agents, &s.Pids, &s.Cmdline, &s.FirstEver, &s.LastEver)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ProgramDest is one destination of a program in the window, with the minutes it was contacted.
type ProgramDest struct {
	Dst     string
	DstPort int
	Proto   string
	Conns   int64
	Bytes   int64
	First   time.Time
	Last    time.Time
	Minutes []time.Time
}

func (d *DB) ProgramDestinationsFor(ctx context.Context, k ProgramKey, w Window, limit int) ([]ProgramDest, error) {
	if limit <= 0 {
		limit = 25
	}
	var args []any
	cond := k.conds(&args)
	args = append(args, w.Since, w.Until, limit)
	rows, err := d.Pool.Query(ctx, fmt.Sprintf(`
SELECT host(dst), dst_port, proto, SUM(count), SUM(bytes), MIN(minute), MAX(minute), ARRAY_AGG(DISTINCT minute ORDER BY minute)
FROM endpoint_conns WHERE %s AND minute >= $%d AND minute < $%d
GROUP BY dst, dst_port, proto ORDER BY SUM(count) DESC LIMIT $%d`, cond, len(args)-2, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProgramDest{}
	for rows.Next() {
		var p ProgramDest
		if err := rows.Scan(&p.Dst, &p.DstPort, &p.Proto, &p.Conns, &p.Bytes, &p.First, &p.Last, &p.Minutes); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DestContext is what else we know about a destination, beyond this program.
type DestContext struct {
	OtherPrograms     []string
	OtherProgramCount int64
	OtherHosts        int64
	OpenAlerts        int64
	AlertTitles       []string
	IDSEvents         int64
	Notes             int64
}

func (d *DB) DestinationContextFor(ctx context.Context, dst string, k ProgramKey, excludeHosts []string, w Window) (*DestContext, error) {
	c := &DestContext{OtherPrograms: []string{}, AlertTitles: []string{}}
	rows, err := d.Pool.Query(ctx, `
SELECT CASE WHEN container <> '' THEN name || ' → ' || container ELSE name END AS label, COUNT(DISTINCT agent_id)
FROM endpoint_conns WHERE dst = $1::inet AND minute >= $2 AND minute < $3 AND NOT (exe = $4 AND "user" = $5 AND container = $6)
GROUP BY label ORDER BY 2 DESC, 1 LIMIT 5`, dst, w.Since, w.Until, k.Exe, k.User, k.Container)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var label string
		var n int64
		if err := rows.Scan(&label, &n); err != nil {
			rows.Close()
			return nil, err
		}
		c.OtherPrograms = append(c.OtherPrograms, label)
	}
	rows.Close()
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(DISTINCT (exe, agent_id)) FROM endpoint_conns WHERE dst = $1::inet AND minute >= $2 AND minute < $3 AND NOT (exe = $4 AND "user" = $5 AND container = $6)`,
		dst, w.Since, w.Until, k.Exe, k.User, k.Container).Scan(&c.OtherProgramCount); err != nil {
		return nil, err
	}
	if excludeHosts == nil {
		excludeHosts = []string{}
	}
	if err := d.Pool.QueryRow(ctx, `
SELECT GREATEST(
  (SELECT COUNT(DISTINCT host) FROM host_peer_daily WHERE peer = $1::inet AND day >= ($2::timestamptz)::date AND NOT (host(host) = ANY($4::text[]))),
  (SELECT COUNT(DISTINCT host) FROM endpoint_conns WHERE dst = $1::inet AND minute >= $2 AND minute < $3 AND NOT (host(host) = ANY($4::text[]))))`,
		dst, w.Since, w.Until, excludeHosts).Scan(&c.OtherHosts); err != nil {
		return nil, err
	}
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*), ARRAY(SELECT title FROM alerts WHERE peer = $1::inet AND state <> 'resolved' ORDER BY last_seen DESC LIMIT 3)
FROM alerts WHERE peer = $1::inet AND state <> 'resolved'`, dst).Scan(&c.OpenAlerts, &c.AlertTitles); err != nil {
		return nil, err
	}
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ids_events WHERE (dst_ip = $1::inet OR src_ip = $1::inet) AND ts >= $2 AND ts < $3`, dst, w.Since, w.Until).Scan(&c.IDSEvents); err != nil {
		return nil, err
	}
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ip_notes WHERE ip = $1::inet`, dst).Scan(&c.Notes); err != nil {
		return nil, err
	}
	return c, nil
}
