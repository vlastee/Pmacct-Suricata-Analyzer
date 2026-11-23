package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// Queries that gather the context a notification needs to explain one alert: the traffic
// between the two addresses, the programs behind it, Suricata events for the pair, and which
// VirusTotal engines flagged the peer.

// PairService is one service (protocol + server port) seen between a host and a peer.
type PairService struct {
	Proto   int
	Port    int
	Flows   int64
	Packets int64
	Bytes   int64
}

// PairTraffic summarises flow records between host and peer in a window, split by direction.
// "Out" is host → peer, "In" is peer → host.
type PairTraffic struct {
	FlowsOut, FlowsIn     int64
	PacketsOut, PacketsIn int64
	BytesOut, BytesIn     int64
	First, Last           *time.Time
	Services              []PairService // top services by flow count
	Inbound               bool          // Services are peer → host (no outbound flows)
}

// PairTraffic returns the flows between host and peer in the window (nil when there are none).
func (d *DB) PairTraffic(ctx context.Context, host, peer string, w Window) (*PairTraffic, error) {
	var t PairTraffic
	err := d.Pool.QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE ip_src = $1::inet), COUNT(*) FILTER (WHERE ip_src = $2::inet),
       COALESCE(SUM(packets) FILTER (WHERE ip_src = $1::inet), 0), COALESCE(SUM(packets) FILTER (WHERE ip_src = $2::inet), 0),
       COALESCE(SUM(bytes) FILTER (WHERE ip_src = $1::inet), 0), COALESCE(SUM(bytes) FILTER (WHERE ip_src = $2::inet), 0),
       MIN(stamp_inserted), MAX(COALESCE(stamp_updated, stamp_inserted))
FROM acct
WHERE ((ip_src = $1::inet AND ip_dst = $2::inet) OR (ip_src = $2::inet AND ip_dst = $1::inet))
  AND stamp_inserted >= $3 AND stamp_inserted < $4`, host, peer, w.Since, w.Until).
		Scan(&t.FlowsOut, &t.FlowsIn, &t.PacketsOut, &t.PacketsIn, &t.BytesOut, &t.BytesIn, &t.First, &t.Last)
	if err != nil {
		return nil, err
	}
	if t.FlowsOut+t.FlowsIn == 0 {
		return nil, nil
	}
	src, dst := host, peer
	if t.FlowsOut == 0 {
		src, dst, t.Inbound = peer, host, true
	}
	rows, err := d.Pool.Query(ctx, `
SELECT ip_proto, port_dst, COUNT(*), SUM(packets), SUM(bytes) FROM acct
WHERE ip_src = $1::inet AND ip_dst = $2::inet AND stamp_inserted >= $3 AND stamp_inserted < $4
GROUP BY 1, 2 ORDER BY 3 DESC, 5 DESC LIMIT 3`, src, dst, w.Since, w.Until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s PairService
		if err := rows.Scan(&s.Proto, &s.Port, &s.Flows, &s.Packets, &s.Bytes); err != nil {
			return nil, err
		}
		t.Services = append(t.Services, s)
	}
	return &t, rows.Err()
}

// PairHistory says how often host and peer talked over a longer lookback.
type PairHistory struct {
	Flows int64
	Days  int64
	First *time.Time
}

// PairHistory counts flow records and distinct days for the pair since `since`.
func (d *DB) PairHistory(ctx context.Context, host, peer string, since time.Time) (*PairHistory, error) {
	var h PairHistory
	err := d.Pool.QueryRow(ctx, `
SELECT COUNT(*), COUNT(DISTINCT date_trunc('day', stamp_inserted)), MIN(stamp_inserted) FROM acct
WHERE ((ip_src = $1::inet AND ip_dst = $2::inet) OR (ip_src = $2::inet AND ip_dst = $1::inet)) AND stamp_inserted >= $3`,
		host, peer, since).Scan(&h.Flows, &h.Days, &h.First)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// EndpointProcess is a program an agent saw talking from host to peer.
type EndpointProcess struct {
	AgentID   int64
	Name      string
	Exe       string
	User      string
	Container string
	PID       int   // most recent PID
	PIDs      int64 // distinct PIDs in the window
	Cmdline   string
	SHA256    string
	Conns     int64
	Bytes     int64
	First     time.Time
	Last      time.Time
	Ports     []int32
}

// EndpointProcessesFor lists the programs on host that connected to peer around the window,
// busiest first.
func (d *DB) EndpointProcessesFor(ctx context.Context, host, peer string, w Window, limit int) ([]EndpointProcess, error) {
	if limit <= 0 {
		limit = 3
	}
	rows, err := d.Pool.Query(ctx, `
SELECT agent_id, name, exe, "user", container,
       (array_agg(pid ORDER BY minute DESC))[1], COUNT(DISTINCT pid),
       (array_agg(cmdline ORDER BY minute DESC))[1], MAX(sha256),
       SUM(count), SUM(bytes), MIN(minute), MAX(minute),
       array_agg(DISTINCT dst_port ORDER BY dst_port)
FROM endpoint_conns
WHERE host = $1::inet AND dst = $2::inet AND minute >= $3 AND minute < $4
GROUP BY agent_id, name, exe, "user", container ORDER BY SUM(count) DESC LIMIT $5`,
		host, peer, w.Since.Add(-2*time.Minute), w.Until.Add(2*time.Minute), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EndpointProcess
	for rows.Next() {
		var p EndpointProcess
		if err := rows.Scan(&p.AgentID, &p.Name, &p.Exe, &p.User, &p.Container, &p.PID, &p.PIDs, &p.Cmdline, &p.SHA256,
			&p.Conns, &p.Bytes, &p.First, &p.Last, &p.Ports); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// IDSPairStat groups Suricata events between two addresses by signature and outcome.
type IDSPairStat struct {
	SID       int64
	Signature string
	Category  string
	Action    string
	Iface     string
	AppProto  string
	Severity  int
	Events    int64
	Last      time.Time
	LastID    int64
}

// IDSForPair lists Suricata events between a and b (either direction) in the window.
func (d *DB) IDSForPair(ctx context.Context, a, b string, w Window, limit int) ([]IDSPairStat, error) {
	if limit <= 0 {
		limit = 3
	}
	rows, err := d.Pool.Query(ctx, `
SELECT COALESCE(sid, 0), COALESCE(signature, ''), COALESCE(category, ''), COALESCE(action, ''),
       COALESCE(raw->>'in_iface', ''), COALESCE(app_proto, ''), COALESCE(MIN(severity), 0),
       COUNT(*), MAX(ts), MAX(id)
FROM ids_events
WHERE ((src_ip = $1::inet AND dst_ip = $2::inet) OR (src_ip = $2::inet AND dst_ip = $1::inet)) AND ts >= $3 AND ts < $4
GROUP BY 1, 2, 3, 4, 5, 6 ORDER BY MIN(severity) NULLS LAST, COUNT(*) DESC LIMIT $5`, a, b, w.Since, w.Until, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IDSPairStat
	for rows.Next() {
		var s IDSPairStat
		if err := rows.Scan(&s.SID, &s.Signature, &s.Category, &s.Action, &s.Iface, &s.AppProto, &s.Severity, &s.Events, &s.Last, &s.LastID); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// VTDetection is one VirusTotal engine's verdict on an IP.
type VTDetection struct {
	Engine   string `json:"engine"`
	Category string `json:"category"` // malicious | suspicious
	Result   string `json:"result"`   // e.g. "malware", "phishing"
}

// VTDetectionsFor returns the engines that flagged ip at the last VirusTotal lookup. ok is false
// when the address was never looked up since engine names started being stored.
func (d *DB) VTDetectionsFor(ctx context.Context, ip string) (dets []VTDetection, ok bool, err error) {
	var raw []byte
	err = d.Pool.QueryRow(ctx, `SELECT vt_detections FROM ip_info WHERE ip = $1::inet`, ip).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, false, nil
	}
	if err != nil || raw == nil {
		return nil, false, err
	}
	if err := json.Unmarshal(raw, &dets); err != nil {
		return nil, false, err
	}
	return dets, true, nil
}
