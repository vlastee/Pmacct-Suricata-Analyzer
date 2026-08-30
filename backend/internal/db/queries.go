package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// local is the SQL fragment testing whether an inet column belongs to the local networks
// (passed as a cidr[] parameter).
func local(col, param string) string {
	return fmt.Sprintf("(%s <<= ANY(%s::cidr[]))", col, param)
}

// Overview computes totals for the window.
func (d *DB) Overview(ctx context.Context, w Window, locals []string) (*Totals, error) {
	q := `
WITH f AS (
  SELECT bytes, packets, ip_src, ip_dst,
         ` + local("ip_src", "$3") + ` AS ls,
         ` + local("ip_dst", "$3") + ` AS ld
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2
)
SELECT COALESCE(SUM(bytes),0), COALESCE(SUM(packets),0), COUNT(*),
       COALESCE(SUM(bytes) FILTER (WHERE NOT ls AND ld),0),
       COALESCE(SUM(bytes) FILTER (WHERE ls AND NOT ld),0),
       COALESCE(SUM(bytes) FILTER (WHERE ls AND ld),0),
       (SELECT COUNT(*) FROM (SELECT ip_src FROM f WHERE ls UNION SELECT ip_dst FROM f WHERE ld) x),
       (SELECT COUNT(*) FROM (SELECT ip_src FROM f WHERE NOT ls UNION SELECT ip_dst FROM f WHERE NOT ld) x)
FROM f`
	var t Totals
	err := d.Pool.QueryRow(ctx, q, w.Since, w.Until, locals).Scan(
		&t.Bytes, &t.Packets, &t.Flows, &t.BytesIn, &t.BytesOut, &t.BytesLocal, &t.LocalHosts, &t.ExternalIPs)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Timeseries buckets traffic by the interval. ip filters to flows involving that IP (optional).
func (d *DB) Timeseries(ctx context.Context, w Window, interval time.Duration, locals []string, ip string) ([]Bucket, error) {
	secs := int64(interval.Seconds())
	if secs < 60 {
		secs = 60
	}
	args := []any{w.Since, w.Until, locals, secs}
	where := ""
	if ip != "" {
		args = append(args, ip)
		where = " AND (ip_src = $5::inet OR ip_dst = $5::inet)"
	}
	q := `
SELECT to_timestamp(floor(extract(epoch FROM stamp_inserted) / $4) * $4) AS bucket,
       SUM(bytes), 
       COALESCE(SUM(bytes) FILTER (WHERE NOT ` + local("ip_src", "$3") + ` AND ` + local("ip_dst", "$3") + `),0),
       COALESCE(SUM(bytes) FILTER (WHERE ` + local("ip_src", "$3") + ` AND NOT ` + local("ip_dst", "$3") + `),0),
       SUM(packets), COUNT(*)
FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2` + where + `
GROUP BY 1 ORDER BY 1`
	rows, err := d.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bucket{}
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.Time, &b.Bytes, &b.BytesIn, &b.BytesOut, &b.Packets, &b.Flows); err != nil {
			return nil, err
		}
		b.Time = b.Time.UTC()
		out = append(out, b)
	}
	return out, rows.Err()
}

// Protocols aggregates traffic by IP protocol.
func (d *DB) Protocols(ctx context.Context, w Window, limit int) ([]ProtoStat, error) {
	rows, err := d.Pool.Query(ctx, `
SELECT ip_proto, SUM(bytes), SUM(packets), COUNT(*) FROM acct
WHERE stamp_inserted >= $1 AND stamp_inserted < $2
GROUP BY 1 ORDER BY 2 DESC LIMIT $3`, w.Since, w.Until, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProtoStat{}
	for rows.Next() {
		var p ProtoStat
		if err := rows.Scan(&p.Proto, &p.Bytes, &p.Packets, &p.Flows); err != nil {
			return nil, err
		}
		p.Name = ProtoName(p.Proto)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Ports aggregates traffic by the "service port" of each flow: the lower of the two ports,
// which is almost always the well-known/server side.
func (d *DB) Ports(ctx context.Context, w Window, limit int) ([]PortStat, error) {
	rows, err := d.Pool.Query(ctx, `
SELECT LEAST(port_src, port_dst) AS port, ip_proto, SUM(bytes), SUM(packets), COUNT(*) FROM acct
WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND ip_proto IN (6, 17, 132)
GROUP BY 1, 2 ORDER BY 3 DESC LIMIT $3`, w.Since, w.Until, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PortStat{}
	for rows.Next() {
		var p PortStat
		if err := rows.Scan(&p.Port, &p.Proto, &p.Bytes, &p.Packets, &p.Flows); err != nil {
			return nil, err
		}
		p.Name = ProtoName(p.Proto)
		p.Service = ServiceName(p.Port)
		out = append(out, p)
	}
	return out, rows.Err()
}

// HostsOptions filters the Hosts query.
type HostsOptions struct {
	Local   *bool  // nil = both
	Sort    string // bytes | bytes_in | bytes_out | flows | peers | last_seen | packets | ip
	Asc     bool   // ascending instead of the default descending
	Search  string // substring match on IP text, hostname, org
	Country string
	ASN     string
	Limit   int
	Offset  int
}

var hostSortCols = map[string]string{
	"bytes": "bytes", "bytes_in": "bytes_in", "bytes_out": "bytes_out", "flows": "flows",
	"peers": "peers", "last_seen": "last_seen", "packets": "packets", "ip": "h.ip",
}

// Hosts lists per-IP traffic summaries, with enrichment for external ones.
func (d *DB) Hosts(ctx context.Context, w Window, locals []string, o HostsOptions) ([]HostStat, int64, error) {
	sortCol, ok := hostSortCols[o.Sort]
	if !ok {
		sortCol = "bytes"
	}
	if o.Limit <= 0 || o.Limit > 1000 {
		o.Limit = 100
	}
	args := []any{w.Since, w.Until, locals}
	filters := []string{}
	if o.Local != nil {
		args = append(args, *o.Local)
		filters = append(filters, fmt.Sprintf("h.local = $%d", len(args)))
	}
	if o.Search != "" {
		args = append(args, "%"+strings.ToLower(o.Search)+"%")
		n := len(args)
		filters = append(filters, fmt.Sprintf("(host(h.ip) LIKE $%d OR lower(n.nickname) LIKE $%d OR lower(i.hostname) LIKE $%d OR lower(i.org) LIKE $%d OR lower(i.as_org) LIKE $%d OR lower(i.isp) LIKE $%d)", n, n, n, n, n, n))
	}
	if o.Country != "" {
		args = append(args, strings.ToUpper(o.Country))
		filters = append(filters, fmt.Sprintf("i.country_code = $%d", len(args)))
	}
	if o.ASN != "" {
		args = append(args, o.ASN)
		filters = append(filters, fmt.Sprintf("i.asn = $%d", len(args)))
	}
	where := ""
	if len(filters) > 0 {
		where = "WHERE " + strings.Join(filters, " AND ")
	}
	base := `
WITH f AS (
  SELECT ip_src, ip_dst, bytes, packets, stamp_inserted,
         ` + local("ip_src", "$3") + ` AS ls, ` + local("ip_dst", "$3") + ` AS ld
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2
),
sides AS (
  SELECT ip_src AS ip, ls AS local, ip_dst AS peer, bytes AS bytes_out, 0::bigint AS bytes_in, packets, stamp_inserted FROM f
  UNION ALL
  SELECT ip_dst, ld, ip_src, 0, bytes, packets, stamp_inserted FROM f
),
h AS (
  SELECT ip, bool_or(local) AS local, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
         SUM(bytes_in + bytes_out) AS bytes, SUM(packets) AS packets, COUNT(*) AS flows,
         COUNT(DISTINCT peer) AS peers, MIN(stamp_inserted) AS first_seen, MAX(stamp_inserted) AS last_seen
  FROM sides GROUP BY ip
)
SELECT %s FROM h LEFT JOIN ip_info i ON i.ip = h.ip LEFT JOIN ip_nicknames n ON n.ip = h.ip ` + where

	var total int64
	if err := d.Pool.QueryRow(ctx, fmt.Sprintf(base, "COUNT(*)"), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, o.Limit, o.Offset)
	sel := `host(h.ip), n.nickname, h.local, h.bytes_in, h.bytes_out, h.bytes, h.packets, h.flows, h.peers, h.first_seen, h.last_seen, ` + namesSubquery("h.ip") + `, ` + ipInfoCols("i")
	dir := "DESC"
	if o.Asc {
		dir = "ASC"
	}
	q := fmt.Sprintf(base, sel) + fmt.Sprintf(" ORDER BY %s %s, h.ip LIMIT $%d OFFSET $%d", sortCol, dir, len(args)-1, len(args))
	rows, err := d.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []HostStat{}
	for rows.Next() {
		var h HostStat
		var info IPInfo
		var infoIP *string
		dest := []any{&h.IP, &h.Nickname, &h.Local, &h.BytesIn, &h.BytesOut, &h.Bytes, &h.Packets, &h.Flows, &h.Peers, &h.FirstSeen, &h.LastSeen, &h.Names}
		dest = append(dest, ipInfoDest(&info, &infoIP)...)
		if err := rows.Scan(dest...); err != nil {
			return nil, 0, err
		}
		if h.Names == nil {
			h.Names = []string{}
		}
		if infoIP != nil {
			info.IP = *infoIP
			finishIPInfo(&info)
			h.Info = &info
		}
		out = append(out, h)
	}
	return out, total, rows.Err()
}

// HostPeers lists the peers of one IP with traffic in both directions.
func (d *DB) HostPeers(ctx context.Context, w Window, locals []string, ip string, limit int) ([]HostStat, error) {
	if limit <= 0 {
		limit = 100
	}
	q := `
WITH f AS (
  SELECT CASE WHEN ip_src = $4::inet THEN ip_dst ELSE ip_src END AS peer,
         CASE WHEN ip_src = $4::inet THEN bytes ELSE 0 END AS bytes_out,
         CASE WHEN ip_src = $4::inet THEN 0 ELSE bytes END AS bytes_in,
         packets, stamp_inserted
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND (ip_src = $4::inet OR ip_dst = $4::inet)
),
h AS (
  SELECT peer AS ip, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, SUM(bytes_in+bytes_out) AS bytes,
         SUM(packets) AS packets, COUNT(*) AS flows, MIN(stamp_inserted) AS first_seen, MAX(stamp_inserted) AS last_seen
  FROM f GROUP BY peer
)
SELECT host(h.ip), n.nickname, ` + local("h.ip", "$3") + `, h.bytes_in, h.bytes_out, h.bytes, h.packets, h.flows, 1::bigint, h.first_seen, h.last_seen, ` + namesSubquery("h.ip") + `, ` + ipInfoCols("i") + `
FROM h LEFT JOIN ip_info i ON i.ip = h.ip LEFT JOIN ip_nicknames n ON n.ip = h.ip ORDER BY h.bytes DESC LIMIT $5`
	rows, err := d.Pool.Query(ctx, q, w.Since, w.Until, locals, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HostStat{}
	for rows.Next() {
		var h HostStat
		var info IPInfo
		var infoIP *string
		dest := []any{&h.IP, &h.Nickname, &h.Local, &h.BytesIn, &h.BytesOut, &h.Bytes, &h.Packets, &h.Flows, &h.Peers, &h.FirstSeen, &h.LastSeen, &h.Names}
		dest = append(dest, ipInfoDest(&info, &infoIP)...)
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		if h.Names == nil {
			h.Names = []string{}
		}
		if infoIP != nil {
			info.IP = *infoIP
			finishIPInfo(&info)
			h.Info = &info
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// HostPorts aggregates the ports one IP talks on.
func (d *DB) HostPorts(ctx context.Context, w Window, ip string, limit int) ([]PortStat, error) {
	if limit <= 0 {
		limit = 25
	}
	rows, err := d.Pool.Query(ctx, `
SELECT LEAST(port_src, port_dst), ip_proto, SUM(bytes), SUM(packets), COUNT(*) FROM acct
WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND (ip_src = $3::inet OR ip_dst = $3::inet) AND ip_proto IN (6,17,132)
GROUP BY 1,2 ORDER BY 3 DESC LIMIT $4`, w.Since, w.Until, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PortStat{}
	for rows.Next() {
		var p PortStat
		if err := rows.Scan(&p.Port, &p.Proto, &p.Bytes, &p.Packets, &p.Flows); err != nil {
			return nil, err
		}
		p.Name = ProtoName(p.Proto)
		p.Service = ServiceName(p.Port)
		out = append(out, p)
	}
	return out, rows.Err()
}

// FlowsOptions filters the raw flows query.
type FlowsOptions struct {
	IP     string
	Port   int
	Proto  int
	Limit  int
	Offset int
}

// Flows returns raw accounting rows, newest first.
func (d *DB) Flows(ctx context.Context, w Window, o FlowsOptions) ([]Flow, error) {
	if o.Limit <= 0 || o.Limit > 5000 {
		o.Limit = 200
	}
	args := []any{w.Since, w.Until}
	conds := []string{"stamp_inserted >= $1", "stamp_inserted < $2"}
	if o.IP != "" {
		args = append(args, o.IP)
		conds = append(conds, fmt.Sprintf("(ip_src = $%d::inet OR ip_dst = $%d::inet)", len(args), len(args)))
	}
	if o.Port > 0 {
		args = append(args, o.Port)
		conds = append(conds, fmt.Sprintf("(port_src = $%d OR port_dst = $%d)", len(args), len(args)))
	}
	if o.Proto > 0 {
		args = append(args, o.Proto)
		conds = append(conds, fmt.Sprintf("ip_proto = $%d", len(args)))
	}
	args = append(args, o.Limit, o.Offset)
	q := `SELECT host(a.ip_src), host(a.ip_dst), ns.nickname, nd.nickname, a.port_src, a.port_dst, a.ip_proto, a.packets, a.bytes, a.stamp_inserted, a.stamp_updated
FROM (SELECT * FROM acct WHERE ` + strings.Join(conds, " AND ") + fmt.Sprintf(" ORDER BY stamp_inserted DESC, bytes DESC LIMIT $%d OFFSET $%d) a", len(args)-1, len(args)) + `
LEFT JOIN ip_nicknames ns ON ns.ip = a.ip_src LEFT JOIN ip_nicknames nd ON nd.ip = a.ip_dst
ORDER BY a.stamp_inserted DESC, a.bytes DESC`
	rows, err := d.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Flow{}
	for rows.Next() {
		var f Flow
		if err := rows.Scan(&f.IPSrc, &f.IPDst, &f.SrcNickname, &f.DstNickname, &f.PortSrc, &f.PortDst, &f.Proto, &f.Packets, &f.Bytes, &f.StampInserted, &f.StampUpdated); err != nil {
			return nil, err
		}
		f.ProtoName = ProtoName(f.Proto)
		out = append(out, f)
	}
	return out, rows.Err()
}

// GroupBy aggregates external traffic by an ip_info column ("country_code", "asn", "org").
func (d *DB) GroupBy(ctx context.Context, w Window, locals []string, dim string, limit int) ([]GroupStat, error) {
	var keyCol, labelCol string
	switch dim {
	case "country":
		keyCol, labelCol = "i.country_code", "i.country"
	case "asn":
		keyCol, labelCol = "i.asn", "i.as_org"
	case "org":
		keyCol, labelCol = "i.org", "i.org"
	case "isp":
		keyCol, labelCol = "i.isp", "i.isp"
	default:
		return nil, fmt.Errorf("unknown dimension %q", dim)
	}
	if limit <= 0 {
		limit = 25
	}
	q := `
WITH f AS (
  SELECT ip_src, ip_dst, bytes, ` + local("ip_src", "$3") + ` AS ls, ` + local("ip_dst", "$3") + ` AS ld
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2
),
ext AS (
  SELECT ip_dst AS ip, bytes AS bytes_out, 0::bigint AS bytes_in FROM f WHERE ls AND NOT ld
  UNION ALL
  SELECT ip_src, 0, bytes FROM f WHERE ld AND NOT ls
)
SELECT COALESCE(` + keyCol + `, '??'), COALESCE(` + labelCol + `, 'Unknown'), COUNT(DISTINCT ext.ip),
       SUM(bytes_in), SUM(bytes_out), SUM(bytes_in+bytes_out), COUNT(*)
FROM ext LEFT JOIN ip_info i ON i.ip = ext.ip
GROUP BY 1, 2 ORDER BY 6 DESC LIMIT $4`
	rows, err := d.Pool.Query(ctx, q, w.Since, w.Until, locals, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GroupStat{}
	for rows.Next() {
		var g GroupStat
		if err := rows.Scan(&g.Key, &g.Label, &g.IPs, &g.BytesIn, &g.BytesOut, &g.Bytes, &g.Flows); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ---- ip_info ----

func ipInfoCols(a string) string {
	cols := []string{"host(ip)", "hostname", "country", "country_code", "region", "city", "lat", "lon", "timezone",
		"asn", "as_org", "isp", "org", "is_hosting", "is_proxy", "is_mobile", "source", "status", "error", "attempts",
		"first_seen", "last_lookup", "updated_at",
		"vt_malicious", "vt_suspicious", "vt_harmless", "vt_undetected", "vt_reputation", "vt_tags", "vt_network",
		"vt_last_analysis", "vt_status", "vt_error", "vt_attempts", "vt_lookup_at"}
	for i, c := range cols {
		if strings.HasPrefix(c, "host(") {
			cols[i] = "host(" + a + ".ip)"
		} else {
			cols[i] = a + "." + c
		}
	}
	return strings.Join(cols, ", ")
}

// ipInfoDest returns scan destinations matching ipInfoCols. Because this may come from a LEFT JOIN,
// the non-null NOT NULL columns are scanned into nullable temporaries.
func ipInfoDest(i *IPInfo, ip **string) []any {
	if i.VT == nil {
		i.VT = &VTResult{}
	}
	v := i.VT
	return []any{ip, &i.Hostname, &i.Country, &i.CountryCode, &i.Region, &i.City, &i.Lat, &i.Lon, &i.Timezone,
		&i.ASN, &i.ASOrg, &i.ISP, &i.Org, &i.IsHosting, &i.IsProxy, &i.IsMobile, &i.Source, nullStr{&i.Status}, &i.Error,
		nullInt{&i.Attempts}, nullTime{&i.FirstSeen}, &i.LastLookup, nullTime{&i.UpdatedAt},
		&v.Malicious, &v.Suspicious, &v.Harmless, &v.Undetected, &v.Reputation, &v.Tags, &v.Network,
		&v.LastAnalysis, nullStr{&v.Status}, &v.Error, nullInt{&v.Attempts}, &v.LookupAt}
}

// finishIPInfo drops the VT sub-record when VirusTotal was never consulted.
func finishIPInfo(i *IPInfo) {
	if i.VT != nil && i.VT.Status == "" {
		i.VT = nil
	}
}

// Small nullable scanners for LEFT JOIN columns.
type nullStr struct{ p *string }
type nullInt struct{ p *int }
type nullTime struct{ p *time.Time }

// pgx supports sql.Scanner; implement Scan for each.
func (n nullStr) Scan(v any) error {
	if v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		*n.p = s
	}
	return nil
}
func (n nullInt) Scan(v any) error {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case int64:
		*n.p = int(x)
	case int32:
		*n.p = int(x)
	}
	return nil
}
func (n nullTime) Scan(v any) error {
	if v == nil {
		return nil
	}
	if t, ok := v.(time.Time); ok {
		*n.p = t
	}
	return nil
}

// GetIPInfo returns enrichment for one IP or nil.
func (d *DB) GetIPInfo(ctx context.Context, ip string) (*IPInfo, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+ipInfoCols("i")+` FROM ip_info i WHERE ip = $1::inet`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	var info IPInfo
	var infoIP *string
	if err := rows.Scan(ipInfoDest(&info, &infoIP)...); err != nil {
		return nil, err
	}
	info.IP = *infoIP
	finishIPInfo(&info)
	return &info, nil
}

// UpsertIPInfo stores enrichment results.
func (d *DB) UpsertIPInfo(ctx context.Context, i *IPInfo) error {
	_, err := d.Pool.Exec(ctx, `
INSERT INTO ip_info (ip, hostname, country, country_code, region, city, lat, lon, timezone, asn, as_org, isp, org,
                     is_hosting, is_proxy, is_mobile, source, status, error, attempts, last_lookup, updated_at)
VALUES ($1::inet, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, now(), now())
ON CONFLICT (ip) DO UPDATE SET
  hostname = COALESCE(EXCLUDED.hostname, ip_info.hostname),
  country = COALESCE(EXCLUDED.country, ip_info.country),
  country_code = COALESCE(EXCLUDED.country_code, ip_info.country_code),
  region = COALESCE(EXCLUDED.region, ip_info.region),
  city = COALESCE(EXCLUDED.city, ip_info.city),
  lat = COALESCE(EXCLUDED.lat, ip_info.lat), lon = COALESCE(EXCLUDED.lon, ip_info.lon),
  timezone = COALESCE(EXCLUDED.timezone, ip_info.timezone),
  asn = COALESCE(EXCLUDED.asn, ip_info.asn), as_org = COALESCE(EXCLUDED.as_org, ip_info.as_org),
  isp = COALESCE(EXCLUDED.isp, ip_info.isp), org = COALESCE(EXCLUDED.org, ip_info.org),
  is_hosting = COALESCE(EXCLUDED.is_hosting, ip_info.is_hosting),
  is_proxy = COALESCE(EXCLUDED.is_proxy, ip_info.is_proxy),
  is_mobile = COALESCE(EXCLUDED.is_mobile, ip_info.is_mobile),
  source = COALESCE(EXCLUDED.source, ip_info.source),
  status = EXCLUDED.status, error = EXCLUDED.error,
  attempts = ip_info.attempts + 1, last_lookup = now(), updated_at = now()`,
		i.IP, i.Hostname, i.Country, i.CountryCode, i.Region, i.City, i.Lat, i.Lon, i.Timezone, i.ASN, i.ASOrg,
		i.ISP, i.Org, i.IsHosting, i.IsProxy, i.IsMobile, i.Source, i.Status, i.Error, 1)
	return err
}

// EnrichmentCandidates returns external IPs seen within the lookback window that have never
// been looked up, are stale, or failed (with exponential-ish backoff on attempts).
func (d *DB) EnrichmentCandidates(ctx context.Context, since time.Time, locals []string, refreshAfter time.Duration, limit int) ([]string, error) {
	q := `
WITH seen AS (
  SELECT ip, SUM(bytes) AS bytes FROM (
    SELECT ip_dst AS ip, bytes FROM acct WHERE stamp_inserted >= $1 AND NOT ` + local("ip_dst", "$2") + `
    UNION ALL
    SELECT ip_src, bytes FROM acct WHERE stamp_inserted >= $1 AND NOT ` + local("ip_src", "$2") + `
  ) x
  WHERE NOT (ip <<= '224.0.0.0/4'::cidr OR ip <<= 'ff00::/8'::cidr OR ip = '0.0.0.0'::inet OR ip = '255.255.255.255'::inet OR ip <<= '100.64.0.0/10'::cidr)
  GROUP BY ip
)
SELECT host(seen.ip) FROM seen LEFT JOIN ip_info i ON i.ip = seen.ip
WHERE i.ip IS NULL
   OR (i.status = 'ok' AND i.last_lookup < now() - $3::interval)
   OR (i.status = 'failed' AND i.last_lookup < now() - (interval '10 minutes' * power(2, LEAST(i.attempts, 8))))
   OR (i.status = 'pending' AND (i.last_lookup IS NULL OR i.last_lookup < now() - interval '1 hour'))
ORDER BY (i.ip IS NULL) DESC, seen.bytes DESC
LIMIT $4`
	rows, err := d.Pool.Query(ctx, q, since, locals, refreshAfter.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// EnrichmentStatus counts ip_info rows by state.
func (d *DB) EnrichmentStatus(ctx context.Context, refreshAfter, vtRefreshAfter time.Duration) (*EnrichmentStatus, error) {
	var s EnrichmentStatus
	err := d.Pool.QueryRow(ctx, `
SELECT COUNT(*), COUNT(*) FILTER (WHERE status='ok'), COUNT(*) FILTER (WHERE status='pending'),
       COUNT(*) FILTER (WHERE status='failed'), COUNT(*) FILTER (WHERE status='ok' AND last_lookup < now() - $1::interval),
       COUNT(*) FILTER (WHERE vt_status='ok'), COUNT(*) FILTER (WHERE vt_status='failed'),
       COUNT(*) FILTER (WHERE vt_lookup_at IS NULL),
       COUNT(*) FILTER (WHERE vt_status='ok' AND vt_lookup_at < now() - $2::interval),
       COUNT(*) FILTER (WHERE vt_lookup_at >= date_trunc('day', now() AT TIME ZONE 'utc') AT TIME ZONE 'utc'),
       COUNT(*) FILTER (WHERE vt_lookup_at >= date_trunc('month', now() AT TIME ZONE 'utc') AT TIME ZONE 'utc'),
       COUNT(*) FILTER (WHERE vt_malicious > 0 OR vt_suspicious > 0)
FROM ip_info`, refreshAfter.String(), vtRefreshAfter.String()).Scan(&s.Total, &s.OK, &s.Pending, &s.Failed, &s.Stale,
		&s.VTDone, &s.VTFailed, &s.VTNever, &s.VTStale, &s.VTUsedToday, &s.VTUsedMonth, &s.VTFlagged)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ListIPInfo returns enrichment records, newest first, with optional search.
func (d *DB) ListIPInfo(ctx context.Context, search string, limit, offset int) ([]IPInfo, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT ` + ipInfoCols("i") + ` FROM ip_info i`
	args := []any{}
	if search != "" {
		args = append(args, "%"+strings.ToLower(search)+"%")
		q += ` WHERE host(i.ip) LIKE $1 OR lower(i.hostname) LIKE $1 OR lower(i.org) LIKE $1 OR lower(i.as_org) LIKE $1 OR lower(i.country) LIKE $1`
	}
	args = append(args, limit, offset)
	q += fmt.Sprintf(" ORDER BY i.updated_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := d.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectIPInfo(rows)
}

func collectIPInfo(rows pgx.Rows) ([]IPInfo, error) {
	out := []IPInfo{}
	for rows.Next() {
		var info IPInfo
		var infoIP *string
		if err := rows.Scan(ipInfoDest(&info, &infoIP)...); err != nil {
			return nil, err
		}
		if infoIP != nil {
			info.IP = *infoIP
		}
		finishIPInfo(&info)
		out = append(out, info)
	}
	return out, rows.Err()
}

// DataRange returns the earliest and latest stamp in acct.
func (d *DB) DataRange(ctx context.Context) (min, max *time.Time, err error) {
	err = d.Pool.QueryRow(ctx, `SELECT MIN(stamp_inserted), MAX(stamp_inserted) FROM acct`).Scan(&min, &max)
	return
}

// ---- VirusTotal lane ----

// UpsertVT stores a VirusTotal result. The ip_info row is created (status pending for the
// geo lane) if it does not exist yet. Geo fields returned by VT fill gaps only.
func (d *DB) UpsertVT(ctx context.Context, ip string, v *VTResult) error {
	_, err := d.Pool.Exec(ctx, `
INSERT INTO ip_info (ip, status, asn, as_org, country_code,
                     vt_malicious, vt_suspicious, vt_harmless, vt_undetected, vt_reputation, vt_tags, vt_network,
                     vt_last_analysis, vt_status, vt_error, vt_attempts, vt_lookup_at, updated_at)
VALUES ($1::inet, 'pending', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 1, now(), now())
ON CONFLICT (ip) DO UPDATE SET
  asn = COALESCE(ip_info.asn, EXCLUDED.asn), as_org = COALESCE(ip_info.as_org, EXCLUDED.as_org),
  country_code = COALESCE(ip_info.country_code, EXCLUDED.country_code),
  vt_malicious = COALESCE(EXCLUDED.vt_malicious, ip_info.vt_malicious),
  vt_suspicious = COALESCE(EXCLUDED.vt_suspicious, ip_info.vt_suspicious),
  vt_harmless = COALESCE(EXCLUDED.vt_harmless, ip_info.vt_harmless),
  vt_undetected = COALESCE(EXCLUDED.vt_undetected, ip_info.vt_undetected),
  vt_reputation = COALESCE(EXCLUDED.vt_reputation, ip_info.vt_reputation),
  vt_tags = COALESCE(EXCLUDED.vt_tags, ip_info.vt_tags),
  vt_network = COALESCE(EXCLUDED.vt_network, ip_info.vt_network),
  vt_last_analysis = COALESCE(EXCLUDED.vt_last_analysis, ip_info.vt_last_analysis),
  vt_status = EXCLUDED.vt_status, vt_error = EXCLUDED.vt_error,
  vt_attempts = ip_info.vt_attempts + 1, vt_lookup_at = now(), updated_at = now()`,
		ip, v.ASN, v.ASOrg, v.CountryCode, v.Malicious, v.Suspicious, v.Harmless, v.Undetected, v.Reputation,
		v.Tags, v.Network, v.LastAnalysis, v.Status, v.Error)
	return err
}

// VTCandidates selects external IPs seen since `since` for VirusTotal lookup, in quota-efficient
// order: never-checked IPs first (largest traffic first), then records older than refreshAfter
// that still appear in the traffic feed, then failed lookups after backoff.
func (d *DB) VTCandidates(ctx context.Context, since time.Time, locals []string, refreshAfter time.Duration, limit int) ([]string, error) {
	q := `
WITH seen AS (
  SELECT ip, SUM(bytes) AS bytes FROM (
    SELECT ip_dst AS ip, bytes FROM acct WHERE stamp_inserted >= $1 AND NOT ` + local("ip_dst", "$2") + `
    UNION ALL
    SELECT ip_src, bytes FROM acct WHERE stamp_inserted >= $1 AND NOT ` + local("ip_src", "$2") + `
  ) x
  WHERE NOT (ip <<= '224.0.0.0/4'::cidr OR ip <<= 'ff00::/8'::cidr OR ip = '0.0.0.0'::inet OR ip = '255.255.255.255'::inet OR ip <<= '100.64.0.0/10'::cidr)
  GROUP BY ip
)
SELECT host(seen.ip) FROM seen LEFT JOIN ip_info i ON i.ip = seen.ip
WHERE i.vt_lookup_at IS NULL
   OR (i.vt_status = 'ok' AND i.vt_lookup_at < now() - $3::interval)
   OR (i.vt_status = 'failed' AND i.vt_lookup_at < now() - (interval '30 minutes' * power(2, LEAST(i.vt_attempts, 6))))
ORDER BY (i.vt_lookup_at IS NULL) DESC, seen.bytes DESC
LIMIT $4`
	rows, err := d.Pool.Query(ctx, q, since, locals, refreshAfter.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// VTUsage counts VirusTotal lookups (IP and file reports share one API quota) performed since
// UTC midnight and since the start of the UTC month (durable across restarts). Note: only the
// latest lookup per record is stored, so this is a lower bound; the scheduler also honours
// provider-side 429s.
func (d *DB) VTUsage(ctx context.Context) (day, month int64, err error) {
	err = d.Pool.QueryRow(ctx, `SELECT
  COUNT(*) FILTER (WHERE vt_lookup_at >= date_trunc('day', now() AT TIME ZONE 'utc') AT TIME ZONE 'utc'),
  COUNT(*) FILTER (WHERE vt_lookup_at >= date_trunc('month', now() AT TIME ZONE 'utc') AT TIME ZONE 'utc')
FROM (SELECT vt_lookup_at FROM ip_info UNION ALL SELECT vt_lookup_at FROM file_intel) x`).Scan(&day, &month)
	return
}

// ---- nicknames ----

// ListNicknames returns all nicknames, optionally filtered by substring on ip/nickname/note.
func (d *DB) ListNicknames(ctx context.Context, search string) ([]Nickname, error) {
	q := `SELECT host(ip), nickname, note, kind, updated_at FROM ip_nicknames`
	args := []any{}
	if search != "" {
		args = append(args, "%"+strings.ToLower(search)+"%")
		q += ` WHERE host(ip) LIKE $1 OR lower(nickname) LIKE $1 OR lower(note) LIKE $1`
	}
	q += ` ORDER BY nickname, ip`
	rows, err := d.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Nickname{}
	for rows.Next() {
		var n Nickname
		if err := rows.Scan(&n.IP, &n.Nickname, &n.Note, &n.Kind, &n.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// GetNickname returns the nickname for an IP or nil.
func (d *DB) GetNickname(ctx context.Context, ip string) (*Nickname, error) {
	var n Nickname
	err := d.Pool.QueryRow(ctx, `SELECT host(ip), nickname, note, kind, updated_at FROM ip_nicknames WHERE ip = $1::inet`, ip).
		Scan(&n.IP, &n.Nickname, &n.Note, &n.Kind, &n.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// SetNickname creates or updates a nickname.
func (d *DB) SetNickname(ctx context.Context, ip, nickname string, note *string, kind string) (*Nickname, error) {
	if kind == "" {
		kind = "other"
	}
	var n Nickname
	err := d.Pool.QueryRow(ctx, `
INSERT INTO ip_nicknames (ip, nickname, note, kind, updated_at) VALUES ($1::inet, $2, $3, $4, now())
ON CONFLICT (ip) DO UPDATE SET nickname = EXCLUDED.nickname, note = EXCLUDED.note, kind = EXCLUDED.kind, updated_at = now()
RETURNING host(ip), nickname, note, kind, updated_at`, ip, nickname, note, kind).Scan(&n.IP, &n.Nickname, &n.Note, &n.Kind, &n.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// DeleteNickname removes a nickname. Returns false if none existed.
func (d *DB) DeleteNickname(ctx context.Context, ip string) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM ip_nicknames WHERE ip = $1::inet`, ip)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// Threats lists external IPs in the window that VirusTotal flagged as malicious or suspicious.
func (d *DB) Threats(ctx context.Context, w Window, locals []string, limit int) ([]Threat, error) {
	if limit <= 0 {
		limit = 100
	}
	q := `
WITH f AS (
  SELECT ip_src, ip_dst, bytes, stamp_inserted, ` + local("ip_src", "$3") + ` AS ls, ` + local("ip_dst", "$3") + ` AS ld
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2
),
ext AS (
  SELECT ip_dst AS ip, ip_src AS peer, bytes, stamp_inserted FROM f WHERE ls AND NOT ld
  UNION ALL
  SELECT ip_src, ip_dst, bytes, stamp_inserted FROM f WHERE ld AND NOT ls
),
agg AS (
  SELECT ip, SUM(bytes) AS bytes, COUNT(*) AS flows, MAX(stamp_inserted) AS last_seen,
         array_agg(DISTINCT host(peer)) AS peers
  FROM ext GROUP BY ip
)
SELECT host(agg.ip), n.nickname, COALESCE(i.vt_malicious,0), COALESCE(i.vt_suspicious,0), COALESCE(i.vt_tags, '{}'), agg.bytes, agg.flows, agg.peers, agg.last_seen, ` + ipInfoCols("i") + `
FROM agg JOIN ip_info i ON i.ip = agg.ip LEFT JOIN ip_nicknames n ON n.ip = agg.ip
WHERE COALESCE(i.vt_malicious,0) > 0 OR COALESCE(i.vt_suspicious,0) > 0
ORDER BY COALESCE(i.vt_malicious,0) DESC, COALESCE(i.vt_suspicious,0) DESC, agg.bytes DESC LIMIT $4`
	rows, err := d.Pool.Query(ctx, q, w.Since, w.Until, locals, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Threat{}
	for rows.Next() {
		var t Threat
		var info IPInfo
		var infoIP *string
		dest := []any{&t.IP, &t.Nickname, &t.Malicious, &t.Suspicious, &t.Tags, &t.Bytes, &t.Flows, &t.LocalHosts, &t.LastSeen}
		dest = append(dest, ipInfoDest(&info, &infoIP)...)
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		if infoIP != nil {
			info.IP = *infoIP
			finishIPInfo(&info)
			t.Info = &info
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
