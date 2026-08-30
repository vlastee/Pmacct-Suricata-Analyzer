package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Agent is an enrolled endpoint agent.
type Agent struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Hostname    string     `json:"hostname"`
	OS          string     `json:"os"`
	Arch        string     `json:"arch"`
	Version     string     `json:"version"`
	IPs         []string   `json:"ips"`
	Capture     string     `json:"capture"`
	EnrolledAt  time.Time  `json:"enrolled_at"`
	LastSeen    *time.Time `json:"last_seen"`
	LastIP      *string    `json:"last_ip"`
	EventsTotal int64      `json:"events_total"`
	LastBatch   int        `json:"last_batch"`
	Dropped     int64      `json:"dropped"`
	RevokedAt   *time.Time `json:"revoked_at"`
	Note        string     `json:"note"`
}

// EndpointConn is one per-minute aggregate reported by an agent.
type EndpointConn struct {
	Minute    time.Time `json:"minute"`
	Host      string    `json:"src"` // local source address
	Proto     string    `json:"proto"`
	Dst       string    `json:"dst"`
	DstPort   int       `json:"dst_port"`
	Exe       string    `json:"exe"`
	Name      string    `json:"name"`
	User      string    `json:"user"`
	SHA256    string    `json:"sha256"`
	PID       int       `json:"pid"`
	Cmdline   string    `json:"cmdline"`
	Container string    `json:"container"`
	Count     int       `json:"count"`
	Bytes     int64     `json:"bytes"`
}

// NewToken returns a random 32-byte token (hex) and its storage hash.
func NewToken() (token, hash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token = hex.EncodeToString(b)
	return token, HashToken(token)
}

// HashToken is how tokens are stored and looked up.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

const agentCols = `id, name, hostname, os, arch, version, ips::text[], capture, enrolled_at, last_seen, host(last_ip), events_total, last_batch, dropped, revoked_at, note`

func scanAgent(row pgx.Row) (*Agent, error) {
	var a Agent
	var ips []string
	if err := row.Scan(&a.ID, &a.Name, &a.Hostname, &a.OS, &a.Arch, &a.Version, &ips, &a.Capture, &a.EnrolledAt, &a.LastSeen, &a.LastIP, &a.EventsTotal, &a.LastBatch, &a.Dropped, &a.RevokedAt, &a.Note); err != nil {
		return nil, err
	}
	a.IPs = ips
	if a.IPs == nil {
		a.IPs = []string{}
	}
	return &a, nil
}

// CreateEnrollToken mints a single-use enrollment token valid for ttl.
func (d *DB) CreateEnrollToken(ctx context.Context, name, createdBy string, ttl time.Duration) (token string, expires time.Time, err error) {
	token, hash := NewToken()
	expires = time.Now().Add(ttl)
	_, err = d.Pool.Exec(ctx, `INSERT INTO agent_enroll_tokens (token_hash, name, created_by, expires_at) VALUES ($1, $2, $3, $4)`, hash, strings.TrimSpace(name), createdBy, expires)
	return token, expires, err
}

// ErrEnrollToken is returned for unknown, expired or already used enrollment tokens.
var ErrEnrollToken = errors.New("invalid or expired enrollment token")

// EnrollAgent consumes an enrollment token and creates the agent, returning its bearer token
// (only ever returned here).
func (d *DB) EnrollAgent(ctx context.Context, enrollToken, hostname, os, arch, version string, ips []string, remoteIP string) (*Agent, string, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	var name string
	err = tx.QueryRow(ctx, `UPDATE agent_enroll_tokens SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING name`, HashToken(enrollToken)).Scan(&name)
	if err == pgx.ErrNoRows {
		return nil, "", ErrEnrollToken
	}
	if err != nil {
		return nil, "", err
	}
	if name == "" {
		name = hostname
	}
	if name == "" {
		name = "agent"
	}
	token, hash := NewToken()
	if ips == nil {
		ips = []string{}
	}
	row := tx.QueryRow(ctx, `INSERT INTO agents (name, hostname, os, arch, version, token_hash, ips, last_seen, last_ip)
VALUES ($1, $2, $3, $4, $5, $6, $7::inet[], now(), NULLIF($8, '')::inet) RETURNING `+agentCols, name, hostname, os, arch, version, hash, ips, remoteIP)
	a, err := scanAgent(row)
	if err != nil {
		return nil, "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_enroll_tokens SET used_by_agent = $1 WHERE token_hash = $2`, a.ID, HashToken(enrollToken)); err != nil {
		return nil, "", err
	}
	return a, token, tx.Commit(ctx)
}

// AgentByToken authenticates a bearer token; nil when unknown or revoked.
func (d *DB) AgentByToken(ctx context.Context, token string) (*Agent, error) {
	a, err := scanAgent(d.Pool.QueryRow(ctx, `SELECT `+agentCols+` FROM agents WHERE token_hash = $1 AND revoked_at IS NULL`, HashToken(token)))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// ListAgents returns all agents, newest first.
func (d *DB) ListAgents(ctx context.Context) ([]Agent, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+agentCols+` FROM agents ORDER BY enrolled_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// CountActiveAgents is a cheap "is attribution data even possible" check.
func (d *DB) CountActiveAgents(ctx context.Context) (int, error) {
	var n int
	err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents WHERE revoked_at IS NULL`).Scan(&n)
	return n, err
}

// UpdateAgent renames / annotates an agent.
func (d *DB) UpdateAgent(ctx context.Context, id int64, name, note string) (*Agent, error) {
	a, err := scanAgent(d.Pool.QueryRow(ctx, `UPDATE agents SET name = COALESCE(NULLIF($2, ''), name), note = $3 WHERE id = $1 RETURNING `+agentCols, id, strings.TrimSpace(name), strings.TrimSpace(note)))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// RevokeAgent invalidates an agent's token (its data is kept).
func (d *DB) RevokeAgent(ctx context.Context, id int64) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `UPDATE agents SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// DeleteAgent removes an agent and everything it reported.
func (d *DB) DeleteAgent(ctx context.Context, id int64) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// TouchAgent records a heartbeat/batch.
func (d *DB) TouchAgent(ctx context.Context, id int64, ips []string, version, capture, remoteIP string, batch int, dropped int64) error {
	if ips == nil {
		ips = []string{}
	}
	_, err := d.Pool.Exec(ctx, `UPDATE agents SET last_seen = now(), ips = CASE WHEN cardinality($2::inet[]) > 0 THEN $2::inet[] ELSE ips END,
version = COALESCE(NULLIF($3, ''), version), capture = COALESCE(NULLIF($4, ''), capture), last_ip = COALESCE(NULLIF($5, '')::inet, last_ip),
events_total = events_total + $6, last_batch = $6, dropped = $7 WHERE id = $1`, id, ips, version, capture, remoteIP, batch, dropped)
	return err
}

// InsertEndpointConns stores a batch, merging duplicates of the same minute/key.
func (d *DB) InsertEndpointConns(ctx context.Context, agentID int64, rows []EndpointConn) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	batch := &pgx.Batch{}
	for _, c := range rows {
		batch.Queue(`INSERT INTO endpoint_conns (agent_id, minute, host, proto, dst, dst_port, exe, name, "user", sha256, pid, cmdline, container, count, bytes)
VALUES ($1, $2, $3::inet, $4, $5::inet, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (agent_id, minute, host, proto, dst, dst_port, exe, "user", container) DO UPDATE SET
  count = endpoint_conns.count + EXCLUDED.count, bytes = endpoint_conns.bytes + EXCLUDED.bytes, pid = EXCLUDED.pid,
  name = EXCLUDED.name, sha256 = EXCLUDED.sha256, cmdline = CASE WHEN EXCLUDED.cmdline <> '' THEN EXCLUDED.cmdline ELSE endpoint_conns.cmdline END`,
			agentID, c.Minute.UTC().Truncate(time.Minute), c.Host, c.Proto, c.Dst, c.DstPort, c.Exe, c.Name, c.User, c.SHA256, c.PID, c.Cmdline, c.Container, c.Count, c.Bytes)
	}
	res := d.Pool.SendBatch(ctx, batch)
	defer res.Close()
	for range rows {
		if _, err := res.Exec(); err != nil {
			return 0, err
		}
	}
	return len(rows), nil
}

// ProcessStat summarises one program's connections from a host in a window.
type ProcessStat struct {
	Exe       string    `json:"exe"`
	Name      string    `json:"name"`
	User      string    `json:"user"`
	Container string    `json:"container"`
	SHA256    string    `json:"sha256"`
	Conns     int64     `json:"conns"`
	Bytes     int64     `json:"bytes"`
	Peers     int64     `json:"peers"`
	Ports     int64     `json:"ports"`
	LastSeen  time.Time `json:"last_seen"`
	TopPeers  []string  `json:"top_peers"`
}

// HostProcesses lists programs that made connections from host in the window.
func (d *DB) HostProcesses(ctx context.Context, host string, w Window, limit int) ([]ProcessStat, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.Pool.Query(ctx, `
WITH c AS (
  SELECT exe, name, "user", container, MAX(sha256) AS sha256, SUM(count) AS conns, SUM(bytes) AS bytes,
         COUNT(DISTINCT dst) AS peers, COUNT(DISTINCT dst_port) AS ports, MAX(minute) AS last_seen
  FROM endpoint_conns WHERE host = $1::inet AND minute >= $2 AND minute < $3
  GROUP BY exe, name, "user", container)
SELECT c.*, (SELECT ARRAY(SELECT host(dst) || ':' || dst_port FROM endpoint_conns e
             WHERE e.host = $1::inet AND e.minute >= $2 AND e.minute < $3 AND e.exe = c.exe AND e."user" = c."user" AND e.container = c.container
             GROUP BY dst, dst_port ORDER BY SUM(count) DESC LIMIT 3)) AS top_peers
FROM c ORDER BY conns DESC LIMIT $4`, host, w.Since, w.Until, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProcessStat{}
	for rows.Next() {
		var p ProcessStat
		if err := rows.Scan(&p.Exe, &p.Name, &p.User, &p.Container, &p.SHA256, &p.Conns, &p.Bytes, &p.Peers, &p.Ports, &p.LastSeen, &p.TopPeers); err != nil {
			return nil, err
		}
		if p.TopPeers == nil {
			p.TopPeers = []string{}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProcessesForPeers maps each peer of host to the programs that talked to it in the window
// (for the "via" column on host pages).
func (d *DB) ProcessesForPeers(ctx context.Context, host string, w Window) (map[string][]string, error) {
	rows, err := d.Pool.Query(ctx, `
SELECT host(dst), name, "user", container, SUM(count) AS n FROM endpoint_conns
WHERE host = $1::inet AND minute >= $2 AND minute < $3 GROUP BY dst, name, "user", container ORDER BY dst, n DESC`, host, w.Since, w.Until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var dst, name, user, container string
		var n int64
		if err := rows.Scan(&dst, &name, &user, &container, &n); err != nil {
			return nil, err
		}
		if len(out[dst]) < 3 {
			out[dst] = append(out[dst], procLabel(name, user, container))
		}
	}
	return out, rows.Err()
}

// ProcessesFor names the programs on host that talked to peer (optionally on port) in the window —
// attached to alerts as "via".
func (d *DB) ProcessesFor(ctx context.Context, host, peer string, port int, w Window, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 3
	}
	args := []any{host, peer, w.Since.Add(-2 * time.Minute), w.Until.Add(2 * time.Minute), limit}
	portCond := ""
	if port > 0 {
		args = append(args, port)
		portCond = fmt.Sprintf(" AND dst_port = $%d", len(args))
	}
	rows, err := d.Pool.Query(ctx, `SELECT name, "user", exe, container, SUM(count) AS n FROM endpoint_conns
WHERE host = $1::inet AND dst = $2::inet AND minute >= $3 AND minute < $4`+portCond+` GROUP BY name, "user", exe, container ORDER BY n DESC LIMIT $5`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, user, exe, container string
		var n int64
		if err := rows.Scan(&name, &user, &exe, &container, &n); err != nil {
			return nil, err
		}
		if name == "" {
			name = exe
		}
		out = append(out, procLabel(name, user, container))
	}
	return out, rows.Err()
}

// procLabel renders "pasta.avx2 → mycontainer (petro)".
func procLabel(name, user, container string) string {
	if container != "" {
		name += " → " + container
	}
	if user != "" {
		return name + " (" + user + ")"
	}
	return name
}

// AgentByID returns one agent (nil when unknown).
func (d *DB) AgentByID(ctx context.Context, id int64) (*Agent, error) {
	a, err := scanAgent(d.Pool.QueryRow(ctx, `SELECT `+agentCols+` FROM agents WHERE id = $1`, id))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// AgentForHost finds the (most recently seen, active) agent that owns a local address.
func (d *DB) AgentForHost(ctx context.Context, host string) (*Agent, error) {
	a, err := scanAgent(d.Pool.QueryRow(ctx, `SELECT `+agentCols+` FROM agents WHERE $1::inet = ANY(ips) AND revoked_at IS NULL ORDER BY last_seen DESC NULLS LAST LIMIT 1`, host))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// PruneEndpointConns drops aggregates older than the retention.
func (d *DB) PruneEndpointConns(ctx context.Context, keep time.Duration) (int64, error) {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM endpoint_conns WHERE minute < now() - $1::interval`, keep.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// AgentActivity is what one agent reported in a window.
type AgentActivity struct {
	Rows         int64            `json:"rows"`
	Conns        int64            `json:"conns"`
	Programs     int64            `json:"programs"`
	Peers        int64            `json:"peers"`
	First        *time.Time       `json:"first"`
	Last         *time.Time       `json:"last"`
	ByProgram    []ProcessStat    `json:"by_program"`
	Destinations []AgentDest      `json:"destinations"`
	Timeline     []AgentBucket    `json:"timeline"`
	Recent       []AgentRecentRow `json:"recent"`
	BucketSecs   int              `json:"bucket_seconds"`
}

type AgentDest struct {
	Dst      string    `json:"dst"`
	DstPort  int       `json:"dst_port"`
	Proto    string    `json:"proto"`
	Conns    int64     `json:"conns"`
	Programs []string  `json:"programs"`
	LastSeen time.Time `json:"last_seen"`
}

type AgentBucket struct {
	At       time.Time `json:"at"`
	Conns    int64     `json:"conns"`
	Programs int64     `json:"programs"`
}

type AgentRecentRow struct {
	Minute    time.Time `json:"minute"`
	Host      string    `json:"src"`
	Proto     string    `json:"proto"`
	Dst       string    `json:"dst"`
	DstPort   int       `json:"dst_port"`
	Name      string    `json:"name"`
	User      string    `json:"user"`
	Container string    `json:"container"`
	Count     int       `json:"count"`
}

// AgentActivityFor summarises one agent's reports in the window.
func (d *DB) AgentActivityFor(ctx context.Context, agentID int64, w Window) (*AgentActivity, error) {
	a := &AgentActivity{ByProgram: []ProcessStat{}, Destinations: []AgentDest{}, Timeline: []AgentBucket{}, Recent: []AgentRecentRow{}}
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*), COALESCE(SUM(count), 0), COUNT(DISTINCT exe), COUNT(DISTINCT dst), MIN(minute), MAX(minute)
FROM endpoint_conns WHERE agent_id = $1 AND minute >= $2 AND minute < $3`, agentID, w.Since, w.Until).Scan(&a.Rows, &a.Conns, &a.Programs, &a.Peers, &a.First, &a.Last); err != nil {
		return nil, err
	}
	rows, err := d.Pool.Query(ctx, `
WITH c AS (
  SELECT exe, name, "user", container, MAX(sha256) AS sha256, SUM(count) AS conns, SUM(bytes) AS bytes,
         COUNT(DISTINCT dst) AS peers, COUNT(DISTINCT dst_port) AS ports, MAX(minute) AS last_seen
  FROM endpoint_conns WHERE agent_id = $1 AND minute >= $2 AND minute < $3 GROUP BY exe, name, "user", container)
SELECT c.*, (SELECT ARRAY(SELECT host(dst) || ':' || dst_port FROM endpoint_conns e
             WHERE e.agent_id = $1 AND e.minute >= $2 AND e.minute < $3 AND e.exe = c.exe AND e."user" = c."user" AND e.container = c.container
             GROUP BY dst, dst_port ORDER BY SUM(count) DESC LIMIT 3)) AS top_peers
FROM c ORDER BY conns DESC LIMIT 100`, agentID, w.Since, w.Until)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p ProcessStat
		if err := rows.Scan(&p.Exe, &p.Name, &p.User, &p.Container, &p.SHA256, &p.Conns, &p.Bytes, &p.Peers, &p.Ports, &p.LastSeen, &p.TopPeers); err != nil {
			rows.Close()
			return nil, err
		}
		if p.TopPeers == nil {
			p.TopPeers = []string{}
		}
		a.ByProgram = append(a.ByProgram, p)
	}
	rows.Close()
	rows, err = d.Pool.Query(ctx, `
SELECT host(dst), dst_port, proto, SUM(count) AS conns, MAX(minute),
       (ARRAY(SELECT CASE WHEN container <> '' THEN name || ' → ' || container ELSE name END FROM endpoint_conns e WHERE e.agent_id = $1 AND e.minute >= $2 AND e.minute < $3 AND e.dst = c.dst AND e.dst_port = c.dst_port AND e.proto = c.proto
              GROUP BY name, container ORDER BY SUM(count) DESC LIMIT 3))
FROM endpoint_conns c WHERE agent_id = $1 AND minute >= $2 AND minute < $3
GROUP BY dst, dst_port, proto ORDER BY conns DESC LIMIT 100`, agentID, w.Since, w.Until)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var x AgentDest
		if err := rows.Scan(&x.Dst, &x.DstPort, &x.Proto, &x.Conns, &x.LastSeen, &x.Programs); err != nil {
			rows.Close()
			return nil, err
		}
		if x.Programs == nil {
			x.Programs = []string{}
		}
		a.Destinations = append(a.Destinations, x)
	}
	rows.Close()
	// Timeline: per minute up to 6 h, then per hour.
	a.BucketSecs = 60
	if w.Until.Sub(w.Since) > 6*time.Hour {
		a.BucketSecs = 3600
	}
	rows, err = d.Pool.Query(ctx, `SELECT to_timestamp(floor(extract(epoch FROM minute) / $4) * $4), SUM(count), COUNT(DISTINCT exe)
FROM endpoint_conns WHERE agent_id = $1 AND minute >= $2 AND minute < $3 GROUP BY 1 ORDER BY 1`, agentID, w.Since, w.Until, a.BucketSecs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var b AgentBucket
		if err := rows.Scan(&b.At, &b.Conns, &b.Programs); err != nil {
			rows.Close()
			return nil, err
		}
		a.Timeline = append(a.Timeline, b)
	}
	rows.Close()
	rows, err = d.Pool.Query(ctx, `SELECT minute, host(host), proto, host(dst), dst_port, name, "user", container, count
FROM endpoint_conns WHERE agent_id = $1 AND minute >= $2 AND minute < $3 ORDER BY minute DESC, count DESC LIMIT 300`, agentID, w.Since, w.Until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r AgentRecentRow
		if err := rows.Scan(&r.Minute, &r.Host, &r.Proto, &r.Dst, &r.DstPort, &r.Name, &r.User, &r.Container, &r.Count); err != nil {
			return nil, err
		}
		a.Recent = append(a.Recent, r)
	}
	return a, rows.Err()
}
