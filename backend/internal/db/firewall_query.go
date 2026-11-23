package db

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// fwAttempt is true for records that are a new connection attempt: any non-TCP packet, or a
// TCP SYN without ACK. pfSense's default deny also logs stray TCP packets that arrive after
// their state expired (FIN/RST/ACK of a finished connection); those are noise, not attempts.
const fwAttempt = `(proto_name IS DISTINCT FROM 'tcp' OR (tcp_flags LIKE '%S%' AND tcp_flags NOT LIKE '%A%'))`

// builtinFWLabels names the rules pfSense generates itself (tracker IDs are fixed).
var builtinFWLabels = map[int64]string{
	1000000103: "Default deny (IPv4)",
	1000000104: "Default deny (IPv6)",
}

// FirewallRuleConf is the user's view of one pfSense rule (settings["fw_rules"], by tracker).
type FirewallRuleConf struct {
	Label    string `json:"label,omitempty"`
	Expected bool   `json:"expected,omitempty"` // blocks by this rule are intended: never alert on them
}

func (d *DB) firewallRuleConfs(ctx context.Context) (map[string]FirewallRuleConf, error) {
	user := map[string]FirewallRuleConf{}
	if _, err := d.GetSetting(ctx, "fw_rules", &user); err != nil {
		return map[string]FirewallRuleConf{}, err
	}
	if user == nil {
		user = map[string]FirewallRuleConf{}
	}
	return user, nil
}

// FirewallRules returns tracker → configuration: built-in names overlaid with the user's.
func (d *DB) FirewallRules(ctx context.Context) (map[int64]FirewallRuleConf, error) {
	out := map[int64]FirewallRuleConf{}
	for k, v := range builtinFWLabels {
		out[k] = FirewallRuleConf{Label: v}
	}
	user, err := d.firewallRuleConfs(ctx)
	for k, v := range user {
		t, perr := strconv.ParseInt(k, 10, 64)
		if perr != nil {
			continue
		}
		c := out[t]
		if v.Label != "" {
			c.Label = v.Label
		}
		c.Expected = v.Expected
		out[t] = c
	}
	return out, err
}

// FirewallRuleLabels returns tracker → label.
func (d *DB) FirewallRuleLabels(ctx context.Context) (map[int64]string, error) {
	rules, err := d.FirewallRules(ctx)
	out := make(map[int64]string, len(rules))
	for k, v := range rules {
		if v.Label != "" {
			out[k] = v.Label
		}
	}
	return out, err
}

// FirewallExpectedTrackers lists rules whose blocks must not raise alerts.
func (d *DB) FirewallExpectedTrackers(ctx context.Context) ([]int64, error) {
	rules, err := d.FirewallRules(ctx)
	out := []int64{}
	for k, v := range rules {
		if v.Expected {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, err
}

// SetFirewallRule stores a rule's label and expected flag (both empty removes the entry).
func (d *DB) SetFirewallRule(ctx context.Context, tracker int64, c FirewallRuleConf) error {
	c.Label = strings.TrimSpace(c.Label)
	if len(c.Label) > 120 {
		return fmt.Errorf("label too long (max 120 characters)")
	}
	user, err := d.firewallRuleConfs(ctx)
	if err != nil {
		return err
	}
	key := strconv.FormatInt(tracker, 10)
	if c.Label == "" && !c.Expected {
		delete(user, key)
	} else {
		user[key] = c
	}
	return d.SetSetting(ctx, "fw_rules", user)
}

// RuleName renders a tracker for people: its label, else "rule <tracker>".
func RuleName(labels map[int64]string, tracker *int64) string {
	if tracker == nil {
		return "unknown rule"
	}
	if l := labels[*tracker]; l != "" {
		return fmt.Sprintf("%q (tracker %d)", l, *tracker)
	}
	return fmt.Sprintf("rule tracker %d", *tracker)
}

// FirewallRuleHit is one (rule, interface, direction, action) group of records.
type FirewallRuleHit struct {
	Action    string    `json:"action"`
	Iface     string    `json:"iface"`
	Direction string    `json:"direction"`
	Tracker   *int64    `json:"tracker"`
	Label     string    `json:"label,omitempty"`
	Outbound  bool      `json:"outbound"` // sent by the first address of the pair / the host
	Packets   int64     `json:"packets"`
	Attempts  int64     `json:"attempts"` // new connection attempts among them
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	Flags     []string  `json:"flags"`
	Ports     []int32   `json:"ports"`
	Peers     int64     `json:"peers,omitempty"`
}

func (d *DB) labelHits(ctx context.Context, hits []FirewallRuleHit) {
	labels, _ := d.FirewallRuleLabels(ctx)
	for i := range hits {
		if hits[i].Tracker != nil {
			hits[i].Label = labels[*hits[i].Tracker]
		}
	}
}

// FirewallForPair returns what the firewall logged between a and b in the window, grouped by
// rule; Outbound means a → b.
func (d *DB) FirewallForPair(ctx context.Context, a, b string, w Window) ([]FirewallRuleHit, error) {
	rows, err := d.Pool.Query(ctx, `
SELECT action, COALESCE(iface, ''), COALESCE(direction, ''), tracker, src_ip = $1::inet,
       COUNT(*), COUNT(*) FILTER (WHERE `+fwAttempt+`), MIN(ts), MAX(ts),
       ARRAY(SELECT DISTINCT x FROM unnest(array_agg(tcp_flags)) x WHERE x IS NOT NULL ORDER BY 1 LIMIT 6),
       ARRAY(SELECT DISTINCT x FROM unnest(array_agg(dst_port)) x WHERE x IS NOT NULL ORDER BY 1 LIMIT 8)
FROM fw_events
WHERE ts >= $3 AND ts < $4
  AND ((src_ip = $1::inet AND dst_ip = $2::inet) OR (src_ip = $2::inet AND dst_ip = $1::inet))
GROUP BY 1, 2, 3, 4, 5 ORDER BY 6 DESC LIMIT 10`, a, b, w.Since, w.Until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FirewallRuleHit{}
	for rows.Next() {
		var h FirewallRuleHit
		if err := rows.Scan(&h.Action, &h.Iface, &h.Direction, &h.Tracker, &h.Outbound, &h.Packets, &h.Attempts, &h.First, &h.Last, &h.Flags, &h.Ports); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	d.labelHits(ctx, out)
	return out, nil
}

// FirewallPeerStat is one peer of a host in the firewall log.
type FirewallPeerStat struct {
	Peer     string    `json:"peer"`
	Nickname *string   `json:"nickname,omitempty"`
	Outbound bool      `json:"outbound"` // host → peer
	Action   string    `json:"action"`
	Packets  int64     `json:"packets"`
	Attempts int64     `json:"attempts"`
	Ports    []int32   `json:"ports"`
	Trackers []int64   `json:"trackers"`
	Last     time.Time `json:"last"`
}

// FirewallHostReport is the firewall view of one address.
type FirewallHostReport struct {
	BlockedOut      int64              `json:"blocked_out"`       // records blocked with the host as source
	BlockedOutTries int64              `json:"blocked_out_tries"` // … that were new connection attempts
	BlockedIn       int64              `json:"blocked_in"`        // records blocked with the host as destination
	BlockedInTries  int64              `json:"blocked_in_tries"`
	Passed          int64              `json:"passed"`
	Rules           []FirewallRuleHit  `json:"rules"`
	Peers           []FirewallPeerStat `json:"peers"`
}

// FirewallForHost summarises the firewall log for one address.
func (d *DB) FirewallForHost(ctx context.Context, ip string, w Window, limit int) (*FirewallHostReport, error) {
	r := &FirewallHostReport{Rules: []FirewallRuleHit{}, Peers: []FirewallPeerStat{}}
	if err := d.Pool.QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE action <> 'pass' AND src_ip = $1::inet),
       COUNT(*) FILTER (WHERE action <> 'pass' AND src_ip = $1::inet AND `+fwAttempt+`),
       COUNT(*) FILTER (WHERE action <> 'pass' AND dst_ip = $1::inet),
       COUNT(*) FILTER (WHERE action <> 'pass' AND dst_ip = $1::inet AND `+fwAttempt+`),
       COUNT(*) FILTER (WHERE action = 'pass')
FROM fw_events WHERE ts >= $2 AND ts < $3 AND (src_ip = $1::inet OR dst_ip = $1::inet)`, ip, w.Since, w.Until).
		Scan(&r.BlockedOut, &r.BlockedOutTries, &r.BlockedIn, &r.BlockedInTries, &r.Passed); err != nil {
		return nil, err
	}
	if r.BlockedOut+r.BlockedIn+r.Passed == 0 {
		return r, nil
	}
	rows, err := d.Pool.Query(ctx, `
SELECT action, COALESCE(iface, ''), COALESCE(direction, ''), tracker, src_ip = $1::inet,
       COUNT(*), COUNT(*) FILTER (WHERE `+fwAttempt+`), MIN(ts), MAX(ts),
       ARRAY(SELECT DISTINCT x FROM unnest(array_agg(tcp_flags)) x WHERE x IS NOT NULL ORDER BY 1 LIMIT 6),
       ARRAY(SELECT DISTINCT x FROM unnest(array_agg(dst_port)) x WHERE x IS NOT NULL ORDER BY 1 LIMIT 8),
       COUNT(DISTINCT CASE WHEN src_ip = $1::inet THEN dst_ip ELSE src_ip END)
FROM fw_events WHERE ts >= $2 AND ts < $3 AND (src_ip = $1::inet OR dst_ip = $1::inet)
GROUP BY 1, 2, 3, 4, 5 ORDER BY 6 DESC LIMIT 15`, ip, w.Since, w.Until)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var h FirewallRuleHit
		if err := rows.Scan(&h.Action, &h.Iface, &h.Direction, &h.Tracker, &h.Outbound, &h.Packets, &h.Attempts, &h.First, &h.Last, &h.Flags, &h.Ports, &h.Peers); err != nil {
			rows.Close()
			return nil, err
		}
		r.Rules = append(r.Rules, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	d.labelHits(ctx, r.Rules)
	rows, err = d.Pool.Query(ctx, `
SELECT host(p.peer), n.nickname, p.outbound, p.action, p.packets, p.attempts, p.ports, p.trackers, p.last
FROM (
  SELECT CASE WHEN src_ip = $1::inet THEN dst_ip ELSE src_ip END AS peer, src_ip = $1::inet AS outbound, action,
         COUNT(*) AS packets, COUNT(*) FILTER (WHERE `+fwAttempt+`) AS attempts,
         ARRAY(SELECT DISTINCT x FROM unnest(array_agg(dst_port)) x WHERE x IS NOT NULL ORDER BY 1 LIMIT 6) AS ports,
         ARRAY(SELECT DISTINCT x FROM unnest(array_agg(tracker)) x WHERE x IS NOT NULL ORDER BY 1 LIMIT 4) AS trackers,
         MAX(ts) AS last
  FROM fw_events WHERE ts >= $2 AND ts < $3 AND (src_ip = $1::inet OR dst_ip = $1::inet)
  GROUP BY 1, 2, 3
) p LEFT JOIN ip_nicknames n ON n.ip = p.peer
WHERE p.peer IS NOT NULL
ORDER BY p.attempts DESC, p.packets DESC LIMIT $4`, ip, w.Since, w.Until, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p FirewallPeerStat
		if err := rows.Scan(&p.Peer, &p.Nickname, &p.Outbound, &p.Action, &p.Packets, &p.Attempts, &p.Ports, &p.Trackers, &p.Last); err != nil {
			return nil, err
		}
		r.Peers = append(r.Peers, p)
	}
	return r, rows.Err()
}

// FirewallFilter narrows the firewall page.
type FirewallFilter struct {
	IP       string // either side
	Action   string // pass | block | reject
	Iface    string
	Port     int // destination port
	Tracker  int64
	Attempts bool // only new connection attempts
}

func (f FirewallFilter) where(w Window, args *[]any) string {
	*args = append(*args, w.Since, w.Until)
	conds := []string{"ts >= $1", "ts < $2"}
	add := func(cond string, v any) {
		*args = append(*args, v)
		conds = append(conds, fmt.Sprintf(cond, len(*args)))
	}
	if f.IP != "" {
		add("(src_ip = $%[1]d::inet OR dst_ip = $%[1]d::inet)", f.IP)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.Iface != "" {
		add("iface = $%d", f.Iface)
	}
	if f.Port > 0 {
		add("dst_port = $%d", f.Port)
	}
	if f.Tracker != 0 {
		add("tracker = $%d", f.Tracker)
	}
	if f.Attempts {
		conds = append(conds, fwAttempt)
	}
	return strings.Join(conds, " AND ")
}

// FirewallTop is one row of a top-N table on the firewall page.
type FirewallTop struct {
	Key      string    `json:"key"` // address, port, or tracker
	Nickname *string   `json:"nickname,omitempty"`
	Label    string    `json:"label,omitempty"`
	Expected bool      `json:"expected,omitempty"`
	Iface    string    `json:"iface,omitempty"`
	Action   string    `json:"action,omitempty"`
	Packets  int64     `json:"packets"`
	Attempts int64     `json:"attempts"`
	Peers    int64     `json:"peers"`
	Last     time.Time `json:"last"`
}

// FirewallPoint is one bucket of the firewall timeline.
type FirewallPoint struct {
	T       time.Time `json:"t"`
	Blocked int64     `json:"blocked"`
	Passed  int64     `json:"passed"`
}

// FirewallSummaryReport backs the firewall page.
type FirewallSummaryReport struct {
	Total        int64           `json:"total"`
	Blocked      int64           `json:"blocked"`
	Passed       int64           `json:"passed"`
	Attempts     int64           `json:"attempts"`      // blocked new connection attempts
	LocalBlocked int64           `json:"local_blocked"` // local hosts with blocked outbound attempts
	Sources      []FirewallTop   `json:"sources"`
	Destinations []FirewallTop   `json:"destinations"`
	Ports        []FirewallTop   `json:"ports"`
	Rules        []FirewallTop   `json:"rules"`
	Series       []FirewallPoint `json:"series"`
	Oldest       *time.Time      `json:"oldest,omitempty"` // earliest stored record (retention horizon)
}

// FirewallSummary aggregates the firewall log for the page.
func (d *DB) FirewallSummary(ctx context.Context, w Window, f FirewallFilter, locals []string, bucket time.Duration, limit int) (*FirewallSummaryReport, error) {
	var args []any
	where := f.where(w, &args)
	r := &FirewallSummaryReport{Sources: []FirewallTop{}, Destinations: []FirewallTop{}, Ports: []FirewallTop{}, Rules: []FirewallTop{}, Series: []FirewallPoint{}}
	largs := append(append([]any{}, args...), locals)
	lp := fmt.Sprintf("$%d", len(largs))
	if err := d.Pool.QueryRow(ctx, `
SELECT COUNT(*), COUNT(*) FILTER (WHERE action <> 'pass'), COUNT(*) FILTER (WHERE action = 'pass'),
       COUNT(*) FILTER (WHERE action <> 'pass' AND `+fwAttempt+`),
       COUNT(DISTINCT src_ip) FILTER (WHERE action <> 'pass' AND `+fwAttempt+` AND `+local("src_ip", lp)+` AND NOT `+local("dst_ip", lp)+`)
FROM fw_events WHERE `+where, largs...).Scan(&r.Total, &r.Blocked, &r.Passed, &r.Attempts, &r.LocalBlocked); err != nil {
		return nil, err
	}
	_ = d.Pool.QueryRow(ctx, `SELECT MIN(ts) FROM fw_events`).Scan(&r.Oldest)
	if r.Total == 0 {
		return r, nil
	}
	targs := append(append([]any{}, args...), limit)
	lim := fmt.Sprintf("$%d", len(targs))
	top := func(sql string, dst *[]FirewallTop, scan func(rows interface{ Scan(...any) error }, t *FirewallTop) error) error {
		rows, err := d.Pool.Query(ctx, sql, targs...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t FirewallTop
			if err := scan(rows, &t); err != nil {
				return err
			}
			*dst = append(*dst, t)
		}
		return rows.Err()
	}
	ipTop := func(col, other string) string {
		return `SELECT host(t.k), n.nickname, t.packets, t.attempts, t.peers, t.last FROM (
  SELECT ` + col + ` AS k, COUNT(*) packets, COUNT(*) FILTER (WHERE ` + fwAttempt + `) attempts, COUNT(DISTINCT ` + other + `) peers, MAX(ts) last
  FROM fw_events WHERE ` + where + ` AND ` + col + ` IS NOT NULL GROUP BY 1) t
LEFT JOIN ip_nicknames n ON n.ip = t.k ORDER BY t.attempts DESC, t.packets DESC LIMIT ` + lim
	}
	ipScan := func(rows interface{ Scan(...any) error }, t *FirewallTop) error {
		return rows.Scan(&t.Key, &t.Nickname, &t.Packets, &t.Attempts, &t.Peers, &t.Last)
	}
	if err := top(ipTop("src_ip", "dst_ip"), &r.Sources, ipScan); err != nil {
		return nil, err
	}
	if err := top(ipTop("dst_ip", "src_ip"), &r.Destinations, ipScan); err != nil {
		return nil, err
	}
	if err := top(`SELECT COALESCE(proto_name, '?') || '/' || dst_port, COUNT(*), COUNT(*) FILTER (WHERE `+fwAttempt+`), COUNT(DISTINCT src_ip), MAX(ts)
FROM fw_events WHERE `+where+` AND dst_port IS NOT NULL GROUP BY proto_name, dst_port ORDER BY 3 DESC, 2 DESC LIMIT `+lim, &r.Ports,
		func(rows interface{ Scan(...any) error }, t *FirewallTop) error {
			return rows.Scan(&t.Key, &t.Packets, &t.Attempts, &t.Peers, &t.Last)
		}); err != nil {
		return nil, err
	}
	if err := top(`SELECT COALESCE(tracker::text, ''), COALESCE(iface, ''), action, COUNT(*), COUNT(*) FILTER (WHERE `+fwAttempt+`), COUNT(DISTINCT src_ip), MAX(ts)
FROM fw_events WHERE `+where+` GROUP BY tracker, iface, action ORDER BY 4 DESC LIMIT `+lim, &r.Rules,
		func(rows interface{ Scan(...any) error }, t *FirewallTop) error {
			return rows.Scan(&t.Key, &t.Iface, &t.Action, &t.Packets, &t.Attempts, &t.Peers, &t.Last)
		}); err != nil {
		return nil, err
	}
	confs, _ := d.FirewallRules(ctx)
	for i := range r.Rules {
		if t, err := strconv.ParseInt(r.Rules[i].Key, 10, 64); err == nil {
			r.Rules[i].Label, r.Rules[i].Expected = confs[t].Label, confs[t].Expected
		}
	}
	sargs := append(append([]any{}, args...), bucket.Seconds())
	rows, err := d.Pool.Query(ctx, fmt.Sprintf(`
SELECT to_timestamp(floor(extract(epoch FROM ts) / $%[1]d) * $%[1]d) AS t,
       COUNT(*) FILTER (WHERE action <> 'pass'), COUNT(*) FILTER (WHERE action = 'pass')
FROM fw_events WHERE %s GROUP BY 1 ORDER BY 1`, len(sargs), where), sargs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p FirewallPoint
		if err := rows.Scan(&p.T, &p.Blocked, &p.Passed); err != nil {
			return nil, err
		}
		r.Series = append(r.Series, p)
	}
	return r, rows.Err()
}

// FirewallEventRow is one record for the event list.
type FirewallEventRow struct {
	TS        time.Time `json:"ts"`
	Action    string    `json:"action"`
	Direction *string   `json:"direction"`
	Iface     *string   `json:"iface"`
	Tracker   *int64    `json:"tracker"`
	Label     string    `json:"label,omitempty"`
	Proto     *string   `json:"proto"`
	Src       *string   `json:"src"`
	SrcNick   *string   `json:"src_nickname,omitempty"`
	SrcPort   *int32    `json:"src_port"`
	Dst       *string   `json:"dst"`
	DstNick   *string   `json:"dst_nickname,omitempty"`
	DstPort   *int32    `json:"dst_port"`
	Length    *int32    `json:"length"`
	TCPFlags  *string   `json:"tcp_flags"`
	ICMPType  *string   `json:"icmp_type"`
	Attempt   bool      `json:"attempt"`
}

// FirewallEvents lists records, newest first.
func (d *DB) FirewallEvents(ctx context.Context, w Window, f FirewallFilter, limit int) ([]FirewallEventRow, error) {
	var args []any
	where := f.where(w, &args)
	args = append(args, limit)
	rows, err := d.Pool.Query(ctx, fmt.Sprintf(`
SELECT e.ts, e.action, e.direction, e.iface, e.tracker, e.proto_name, host(e.src_ip), ns.nickname, e.src_port,
       host(e.dst_ip), nd.nickname, e.dst_port, e.length, e.tcp_flags, e.icmp_type, %s
FROM (SELECT * FROM fw_events WHERE %s ORDER BY ts DESC LIMIT $%d) e
LEFT JOIN ip_nicknames ns ON ns.ip = e.src_ip LEFT JOIN ip_nicknames nd ON nd.ip = e.dst_ip
ORDER BY e.ts DESC`, strings.ReplaceAll(fwAttempt, "proto_name", "e.proto_name"), where, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FirewallEventRow{}
	for rows.Next() {
		var e FirewallEventRow
		if err := rows.Scan(&e.TS, &e.Action, &e.Direction, &e.Iface, &e.Tracker, &e.Proto, &e.Src, &e.SrcNick, &e.SrcPort,
			&e.Dst, &e.DstNick, &e.DstPort, &e.Length, &e.TCPFlags, &e.ICMPType, &e.Attempt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	labels, _ := d.FirewallRuleLabels(ctx)
	for i := range out {
		if out[i].Tracker != nil {
			out[i].Label = labels[*out[i].Tracker]
		}
	}
	return out, nil
}

// FirewallBlockHit is a local host whose outbound connection attempts pfSense blocked.
type FirewallBlockHit struct {
	Host     string
	Attempts int64
	Peers    int64
	Sample   []string // "ip:port" of the most-blocked destinations
	Trackers []int64
}

// DetectFirewallBlockedOutbound finds local hosts with at least minAttempts blocked outbound
// connection attempts to at least minPeers external destinations.
func (d *DB) DetectFirewallBlockedOutbound(ctx context.Context, w Window, locals []string, minAttempts, minPeers int, expected []int64) ([]FirewallBlockHit, error) {
	if expected == nil {
		expected = []int64{}
	}
	rows, err := d.Pool.Query(ctx, `
WITH b AS (
  SELECT src_ip, dst_ip, dst_port, tracker FROM fw_events
  WHERE ts >= $1 AND ts < $2 AND action <> 'pass' AND `+fwAttempt+`
    AND `+local("src_ip", "$3")+` AND NOT `+local("dst_ip", "$3")+`
    AND NOT (dst_ip <<= '224.0.0.0/4'::cidr OR dst_ip = '255.255.255.255'::inet OR dst_ip <<= 'ff00::/8'::cidr)
    AND NOT (tracker IS NOT NULL AND tracker = ANY($6::bigint[]))
), d AS (
  SELECT src_ip, dst_ip, dst_port, COUNT(*) n FROM b GROUP BY 1, 2, 3
)
SELECT host(b.src_ip), COUNT(*), COUNT(DISTINCT b.dst_ip),
       ARRAY(SELECT host(d.dst_ip) || COALESCE(':' || d.dst_port, '') FROM d WHERE d.src_ip = b.src_ip ORDER BY d.n DESC LIMIT 5),
       ARRAY(SELECT DISTINCT x FROM unnest(array_agg(b.tracker)) x WHERE x IS NOT NULL ORDER BY 1 LIMIT 5)
FROM b GROUP BY b.src_ip HAVING COUNT(*) >= $4 AND COUNT(DISTINCT b.dst_ip) >= $5
ORDER BY 2 DESC LIMIT 200`, w.Since, w.Until, locals, minAttempts, minPeers, expected)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FirewallBlockHit{}
	for rows.Next() {
		var h FirewallBlockHit
		if err := rows.Scan(&h.Host, &h.Attempts, &h.Peers, &h.Sample, &h.Trackers); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// FirewallBlockedPeers counts distinct destinations a host's attempts were blocked to.
func (d *DB) FirewallBlockedPeers(ctx context.Context, host string, w Window) (int64, error) {
	var n int64
	err := d.Pool.QueryRow(ctx, `SELECT COUNT(DISTINCT dst_ip) FROM fw_events
WHERE ts >= $2 AND ts < $3 AND src_ip = $1::inet AND action <> 'pass' AND `+fwAttempt, host, w.Since, w.Until).Scan(&n)
	return n, err
}

// FirewallBlockedTo counts blocked connection attempts toward dst in the window.
func (d *DB) FirewallBlockedTo(ctx context.Context, dst string, w Window) (int64, error) {
	var n int64
	err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM fw_events
WHERE ts >= $2 AND ts < $3 AND dst_ip = $1::inet AND action <> 'pass' AND `+fwAttempt, dst, w.Since, w.Until).Scan(&n)
	return n, err
}

// SummarizeBlocks condenses pair hits into "blocked by …" facts for prose: outbound blocks
// only, biggest first.
func SummarizeBlocks(hits []FirewallRuleHit) (packets, attempts int64, rules []string) {
	type agg struct {
		name string
		n    int64
	}
	var as []agg
	for _, h := range hits {
		if !h.Outbound || h.Action == "pass" {
			continue
		}
		packets += h.Packets
		attempts += h.Attempts
		name := "rule tracker ?"
		if h.Tracker != nil {
			name = fmt.Sprintf("rule tracker %d", *h.Tracker)
			if h.Label != "" {
				name = fmt.Sprintf("%q (tracker %d)", h.Label, *h.Tracker)
			}
		}
		if h.Iface != "" {
			name += " on " + h.Iface
		}
		as = append(as, agg{name, h.Packets})
	}
	sort.SliceStable(as, func(i, j int) bool { return as[i].n > as[j].n })
	for _, a := range as {
		rules = append(rules, a.name)
	}
	return packets, attempts, rules
}
