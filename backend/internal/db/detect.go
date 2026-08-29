package db

import (
	"context"
	"time"
)

// This file holds the SQL behind the detection rules. Each function returns plain rows;
// the rules engine turns them into Findings and applies thresholds/exemptions.

// ThreatHit is traffic between a local host and a listed IP.
type ThreatHit struct {
	Host, Peer string
	Lists      []string
	Bytes      int64
	Flows      int64
	HasIn      bool // peer -> host traffic seen
	HasOut     bool // host -> peer traffic seen
}

// DetectThreatListHits finds local<->listed-IP traffic in the window.
func (d *DB) DetectThreatListHits(ctx context.Context, w Window, locals []string) ([]ThreatHit, error) {
	rows, err := d.Pool.Query(ctx, `
WITH f AS (
  SELECT ip_src, ip_dst, bytes, `+local("ip_src", "$3")+` AS ls, `+local("ip_dst", "$3")+` AS ld
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2
),
ext AS (
  SELECT ip_src AS host, ip_dst AS peer, bytes, true AS outb FROM f WHERE ls AND NOT ld
  UNION ALL
  SELECT ip_dst, ip_src, bytes, false FROM f WHERE ld AND NOT ls
),
hits AS (
  SELECT e.host, e.peer, e.bytes, e.outb, t.list FROM ext e JOIN threat_lists t ON e.peer <<= t.net
)
SELECT host(host), host(peer), array_agg(DISTINCT list), SUM(bytes), COUNT(*), bool_or(NOT outb), bool_or(outb)
FROM hits GROUP BY host, peer ORDER BY 4 DESC LIMIT 500`, w.Since, w.Until, locals)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatHit{}
	for rows.Next() {
		var h ThreatHit
		if err := rows.Scan(&h.Host, &h.Peer, &h.Lists, &h.Bytes, &h.Flows, &h.HasIn, &h.HasOut); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ReputationHit is traffic with a peer flagged by VirusTotal or another reputation source.
type ReputationHit struct {
	Host, Peer  string
	Malicious   int
	Suspicious  int
	Sources     []string
	Bytes       int64
	Flows       int64
	HasIn       bool
	HasOut      bool
	CountryCode *string
	ASOrg       *string
}

// DetectReputationHits finds local<->flagged-peer traffic (VT malicious >= minMal, or flagged reputation rows).
func (d *DB) DetectReputationHits(ctx context.Context, w Window, locals []string, minMal int) ([]ReputationHit, error) {
	rows, err := d.Pool.Query(ctx, `
WITH f AS (
  SELECT ip_src, ip_dst, bytes, `+local("ip_src", "$3")+` AS ls, `+local("ip_dst", "$3")+` AS ld
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2
),
ext AS (
  SELECT ip_src AS host, ip_dst AS peer, bytes, true AS outb FROM f WHERE ls AND NOT ld
  UNION ALL
  SELECT ip_dst, ip_src, bytes, false FROM f WHERE ld AND NOT ls
),
flag AS (
  SELECT i.ip, COALESCE(i.vt_malicious,0) AS mal, COALESCE(i.vt_suspicious,0) AS sus, i.country_code, i.as_org,
         ARRAY(SELECT source FROM ip_reputation r WHERE r.ip = i.ip AND r.flagged) ||
         CASE WHEN COALESCE(i.vt_malicious,0) >= $4 THEN ARRAY['virustotal'] ELSE ARRAY[]::text[] END AS sources
  FROM ip_info i
)
SELECT host(e.host), host(e.peer), fl.mal, fl.sus, fl.sources, SUM(e.bytes), COUNT(*), bool_or(NOT e.outb), bool_or(e.outb), fl.country_code, fl.as_org
FROM ext e JOIN flag fl ON fl.ip = e.peer
WHERE array_length(fl.sources, 1) > 0
GROUP BY e.host, e.peer, fl.mal, fl.sus, fl.sources, fl.country_code, fl.as_org ORDER BY fl.mal DESC, 6 DESC LIMIT 500`,
		w.Since, w.Until, locals, minMal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReputationHit{}
	for rows.Next() {
		var h ReputationHit
		if err := rows.Scan(&h.Host, &h.Peer, &h.Malicious, &h.Suspicious, &h.Sources, &h.Bytes, &h.Flows, &h.HasIn, &h.HasOut, &h.CountryCode, &h.ASOrg); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// PortUse is a local host talking to external hosts on a given destination port.
type PortUse struct {
	Host    string
	Port    int
	Proto   int
	Peers   int64
	TopPeer string
	Bytes   int64
	Flows   int64
}

// DetectSuspiciousPorts finds outbound connections from local hosts to the given ports.
func (d *DB) DetectSuspiciousPorts(ctx context.Context, w Window, locals []string, ports []int) ([]PortUse, error) {
	rows, err := d.Pool.Query(ctx, `
WITH f AS (
  SELECT ip_src, ip_dst, port_dst, ip_proto, bytes FROM acct
  WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND port_dst = ANY($4) AND ip_proto IN (6, 17)
    AND `+local("ip_src", "$3")+` AND NOT `+local("ip_dst", "$3")+`
),
peers AS (SELECT ip_src, port_dst, ip_proto, ip_dst, SUM(bytes) b, COUNT(*) n FROM f GROUP BY 1,2,3,4)
SELECT host(ip_src), port_dst, ip_proto, COUNT(*), host((array_agg(ip_dst ORDER BY b DESC))[1]), SUM(b), SUM(n)
FROM peers GROUP BY 1,2,3 ORDER BY 6 DESC LIMIT 500`, w.Since, w.Until, locals, ports)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PortUse{}
	for rows.Next() {
		var p PortUse
		if err := rows.Scan(&p.Host, &p.Port, &p.Proto, &p.Peers, &p.TopPeer, &p.Bytes, &p.Flows); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ScanHit is a source probing many ports on one target, or many targets.
type ScanHit struct {
	Src, Dst   string // Dst empty for horizontal scans
	Ports      int64
	Hosts      int64
	Flows      int64
	AvgPackets float64
	TopPort    int
	SrcLocal   bool
	DstLocal   bool
}

// DetectPortScans finds (src,dst) pairs with many distinct low destination ports and tiny flows.
func (d *DB) DetectPortScans(ctx context.Context, w Window, locals []string, minPorts int, maxAvgPackets float64) ([]ScanHit, error) {
	rows, err := d.Pool.Query(ctx, `
SELECT host(ip_src), host(ip_dst), COUNT(DISTINCT port_dst), COUNT(*), SUM(packets)::float / COUNT(*),
       `+local("ip_src", "$3")+`, `+local("ip_dst", "$3")+`
FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND ip_proto IN (6, 17) AND port_src >= 1024 AND port_dst < 10000
GROUP BY ip_src, ip_dst
HAVING COUNT(DISTINCT port_dst) >= $4 AND SUM(packets)::float / COUNT(*) <= $5
ORDER BY 3 DESC LIMIT 200`, w.Since, w.Until, locals, minPorts, maxAvgPackets)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanHit{}
	for rows.Next() {
		var s ScanHit
		if err := rows.Scan(&s.Src, &s.Dst, &s.Ports, &s.Flows, &s.AvgPackets, &s.SrcLocal, &s.DstLocal); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DetectHostScans finds sources contacting many distinct hosts with tiny flows.
func (d *DB) DetectHostScans(ctx context.Context, w Window, locals []string, minHosts int, maxAvgPackets float64) ([]ScanHit, error) {
	rows, err := d.Pool.Query(ctx, `
SELECT host(ip_src), COUNT(DISTINCT ip_dst), COUNT(*), SUM(packets)::float / COUNT(*), mode() WITHIN GROUP (ORDER BY port_dst),
       `+local("ip_src", "$3")+`
FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND ip_proto IN (6, 17, 1) AND port_src >= 1024
  AND NOT (ip_dst <<= '224.0.0.0/4'::cidr OR ip_dst = '255.255.255.255'::inet OR ip_dst <<= 'ff00::/8'::cidr)
GROUP BY ip_src
HAVING COUNT(DISTINCT ip_dst) >= $4 AND SUM(packets)::float / COUNT(*) <= $5
ORDER BY 2 DESC LIMIT 200`, w.Since, w.Until, locals, minHosts, maxAvgPackets)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanHit{}
	for rows.Next() {
		var s ScanHit
		if err := rows.Scan(&s.Src, &s.Hosts, &s.Flows, &s.AvgPackets, &s.TopPort, &s.SrcLocal); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// BruteHit is an external source hammering one local service.
type BruteHit struct {
	Src, Dst string
	Port     int
	Proto    int
	Flows    int64
	AvgBytes float64
}

// DetectBruteForce finds external->local (src, dst, port) triples with many small flows.
func (d *DB) DetectBruteForce(ctx context.Context, w Window, locals []string, minFlows int, maxAvgBytes float64) ([]BruteHit, error) {
	rows, err := d.Pool.Query(ctx, `
SELECT host(ip_src), host(ip_dst), port_dst, ip_proto, COUNT(*), SUM(bytes)::float / COUNT(*)
FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND ip_proto IN (6, 17)
  AND NOT `+local("ip_src", "$3")+` AND `+local("ip_dst", "$3")+`
GROUP BY ip_src, ip_dst, port_dst, ip_proto
HAVING COUNT(*) >= $4 AND SUM(bytes)::float / COUNT(*) <= $5
ORDER BY 5 DESC LIMIT 200`, w.Since, w.Until, locals, minFlows, maxAvgBytes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BruteHit{}
	for rows.Next() {
		var b BruteHit
		if err := rows.Scan(&b.Src, &b.Dst, &b.Port, &b.Proto, &b.Flows, &b.AvgBytes); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// OneWayHit is a local host with unanswered outbound flows.
type OneWayHit struct {
	Host   string
	Peers  int64
	Flows  int64
	Sample []string
}

// DetectOneWay finds local hosts with >= minPeers external peers that never answered in the window.
func (d *DB) DetectOneWay(ctx context.Context, w Window, locals []string, minPeers int) ([]OneWayHit, error) {
	rows, err := d.Pool.Query(ctx, `
WITH f AS (
  SELECT ip_src, ip_dst, bytes, `+local("ip_src", "$3")+` AS ls, `+local("ip_dst", "$3")+` AS ld
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND ip_proto IN (6, 17)
    AND NOT (ip_dst <<= '224.0.0.0/4'::cidr OR ip_dst = '255.255.255.255'::inet OR ip_dst <<= 'ff00::/8'::cidr)
),
o AS (SELECT ip_src AS host, ip_dst AS peer, SUM(bytes) b, COUNT(*) n FROM f WHERE ls AND NOT ld GROUP BY 1,2),
back AS (SELECT DISTINCT ip_dst AS host, ip_src AS peer FROM f WHERE ld AND NOT ls)
SELECT host(o.host), COUNT(*), SUM(o.n), (array_agg(host(o.peer) ORDER BY o.b DESC))[1:5]
FROM o LEFT JOIN back b ON b.host = o.host AND b.peer = o.peer
WHERE b.host IS NULL GROUP BY o.host HAVING COUNT(*) >= $4 ORDER BY 2 DESC LIMIT 200`, w.Since, w.Until, locals, minPeers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OneWayHit{}
	for rows.Next() {
		var h OneWayHit
		if err := rows.Scan(&h.Host, &h.Peers, &h.Flows, &h.Sample); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// OneWayFlagged marks unanswered outbound attempts to listed/flagged peers (e.g. blocked C2 callbacks).
type OneWayFlagged struct {
	Host, Peer string
	Reasons    []string
	Flows      int64
}

// DetectOneWayFlagged finds unanswered outbound flows toward threat-listed or reputation-flagged peers.
func (d *DB) DetectOneWayFlagged(ctx context.Context, w Window, locals []string, minMal int) ([]OneWayFlagged, error) {
	rows, err := d.Pool.Query(ctx, `
WITH f AS (
  SELECT ip_src, ip_dst, `+local("ip_src", "$3")+` AS ls, `+local("ip_dst", "$3")+` AS ld
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND ip_proto IN (6, 17)
),
o AS (SELECT ip_src AS host, ip_dst AS peer, COUNT(*) n FROM f WHERE ls AND NOT ld GROUP BY 1,2),
back AS (SELECT DISTINCT ip_dst AS host, ip_src AS peer FROM f WHERE ld AND NOT ls),
ow AS (SELECT o.* FROM o LEFT JOIN back b ON b.host = o.host AND b.peer = o.peer WHERE b.host IS NULL),
reasons AS (
  SELECT ow.host, ow.peer, ow.n,
    ARRAY(SELECT 'list:' || t.list FROM threat_lists t WHERE ow.peer <<= t.net) ||
    ARRAY(SELECT 'rep:' || r.source FROM ip_reputation r WHERE r.ip = ow.peer AND r.flagged) ||
    CASE WHEN EXISTS (SELECT 1 FROM ip_info i WHERE i.ip = ow.peer AND COALESCE(i.vt_malicious,0) >= $4) THEN ARRAY['virustotal'] ELSE ARRAY[]::text[] END AS why
  FROM ow
)
SELECT host(host), host(peer), why, n FROM reasons WHERE array_length(why, 1) > 0 ORDER BY n DESC LIMIT 200`,
		w.Since, w.Until, locals, minMal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OneWayFlagged{}
	for rows.Next() {
		var h OneWayFlagged
		if err := rows.Scan(&h.Host, &h.Peer, &h.Reasons, &h.Flows); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// DNSUse is a local host's DNS traffic toward an external resolver.
type DNSUse struct {
	Host, Resolver string
	Port           int
	Flows          int64
	Bytes          int64
}

// DetectExternalDNS finds local hosts (excluding `exempt`) sending DNS/DoT to external resolvers not in `allowed`.
func (d *DB) DetectExternalDNS(ctx context.Context, w Window, locals []string, exempt, allowed []string) ([]DNSUse, error) {
	if allowed == nil {
		allowed = []string{}
	}
	if exempt == nil {
		exempt = []string{}
	}
	rows, err := d.Pool.Query(ctx, `
SELECT host(ip_src), host(ip_dst), port_dst, COUNT(*), SUM(bytes)
FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND port_dst IN (53, 853)
  AND `+local("ip_src", "$3")+` AND NOT `+local("ip_dst", "$3")+`
  AND NOT (host(ip_src) = ANY($4)) AND NOT (host(ip_dst) = ANY($5))
GROUP BY 1,2,3 ORDER BY 4 DESC LIMIT 200`, w.Since, w.Until, locals, exempt, allowed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSUse{}
	for rows.Next() {
		var u DNSUse
		if err := rows.Scan(&u.Host, &u.Resolver, &u.Port, &u.Flows, &u.Bytes); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// HostVolume is a per-host aggregate.
type HostVolume struct {
	Host  string
	Flows int64
	Bytes int64
}

// DetectDNSVolume finds local hosts with unusually many DNS flows or bytes in the window.
func (d *DB) DetectDNSVolume(ctx context.Context, w Window, locals []string, exempt []string, minFlows int, minBytes int64) ([]HostVolume, error) {
	if exempt == nil {
		exempt = []string{}
	}
	rows, err := d.Pool.Query(ctx, `
SELECT host(ip_src), COUNT(*), SUM(bytes) FROM acct
WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND port_dst = 53 AND `+local("ip_src", "$3")+` AND NOT (host(ip_src) = ANY($4))
GROUP BY 1 HAVING COUNT(*) >= $5 OR SUM(bytes) >= $6 ORDER BY 2 DESC LIMIT 100`, w.Since, w.Until, locals, exempt, minFlows, minBytes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HostVolume{}
	for rows.Next() {
		var v HostVolume
		if err := rows.Scan(&v.Host, &v.Flows, &v.Bytes); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GeoHit is traffic with a peer in a watched country.
type GeoHit struct {
	Host, Peer  string
	CountryCode string
	Country     *string
	ASOrg       *string
	Bytes       int64
	Flows       int64
}

// DetectGeo finds local<->external traffic with peers located in the given countries.
func (d *DB) DetectGeo(ctx context.Context, w Window, locals []string, countries []string) ([]GeoHit, error) {
	rows, err := d.Pool.Query(ctx, `
WITH f AS (
  SELECT ip_src, ip_dst, bytes, `+local("ip_src", "$3")+` AS ls, `+local("ip_dst", "$3")+` AS ld
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2
),
ext AS (
  SELECT ip_src AS host, ip_dst AS peer, bytes FROM f WHERE ls AND NOT ld
  UNION ALL SELECT ip_dst, ip_src, bytes FROM f WHERE ld AND NOT ls
)
SELECT host(e.host), host(e.peer), i.country_code, i.country, i.as_org, SUM(e.bytes), COUNT(*)
FROM ext e JOIN ip_info i ON i.ip = e.peer WHERE i.country_code = ANY($4)
GROUP BY 1,2,3,4,5 ORDER BY 6 DESC LIMIT 300`, w.Since, w.Until, locals, countries)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GeoHit{}
	for rows.Next() {
		var g GeoHit
		if err := rows.Scan(&g.Host, &g.Peer, &g.CountryCode, &g.Country, &g.ASOrg, &g.Bytes, &g.Flows); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// VolumeAnomaly is a host whose outbound volume for an hour is far above its baseline.
type VolumeAnomaly struct {
	Host     string
	BytesOut int64
	Median   float64
	MAD      float64
	Samples  int64
}

// DetectVolumeAnomalies compares host_hourly.bytes_out at `hour` with the same hour-of-day over the
// previous `days` days (median + factor * MAD, with a floor of 10% of the median).
func (d *DB) DetectVolumeAnomalies(ctx context.Context, hour time.Time, days, minSamples int, minBytes int64, factor float64) ([]VolumeAnomaly, error) {
	rows, err := d.Pool.Query(ctx, `
WITH cur AS (SELECT host, bytes_out FROM host_hourly WHERE hour = $1),
hist AS (
  SELECT host, bytes_out FROM host_hourly
  WHERE hour < $1 AND hour >= $1 - ($2::int * interval '1 day') AND EXTRACT(hour FROM hour AT TIME ZONE 'utc') = EXTRACT(hour FROM $1::timestamptz AT TIME ZONE 'utc')
),
stats AS (SELECT host, COUNT(*) n, percentile_cont(0.5) WITHIN GROUP (ORDER BY bytes_out) med FROM hist GROUP BY host),
mad AS (SELECT h.host, percentile_cont(0.5) WITHIN GROUP (ORDER BY abs(h.bytes_out - s.med)) mad FROM hist h JOIN stats s USING (host) GROUP BY h.host)
SELECT host(c.host), c.bytes_out, s.med, m.mad, s.n
FROM cur c JOIN stats s USING (host) JOIN mad m USING (host)
WHERE s.n >= $3 AND c.bytes_out >= $4 AND c.bytes_out > s.med + $5 * GREATEST(m.mad, s.med * 0.1, 1048576)
ORDER BY c.bytes_out DESC LIMIT 100`, hour, days, minSamples, minBytes, factor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VolumeAnomaly{}
	for rows.Next() {
		var v VolumeAnomaly
		if err := rows.Scan(&v.Host, &v.BytesOut, &v.Median, &v.MAD, &v.Samples); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// NewHost is a local host first seen recently.
type NewHost struct {
	Host      string
	FirstSeen time.Time
	Bytes     int64
}

// DetectNewHosts returns local hosts whose earliest rollup hour is >= since. Returns nothing unless
// the rollups have at least `minHistory` of history, to avoid a flood on first deployment.
func (d *DB) DetectNewHosts(ctx context.Context, since time.Time, minHistory time.Duration) ([]NewHost, error) {
	var oldest *time.Time
	if err := d.Pool.QueryRow(ctx, `SELECT MIN(hour) FROM host_hourly`).Scan(&oldest); err != nil {
		return nil, err
	}
	if oldest == nil || time.Since(*oldest) < minHistory {
		return nil, nil
	}
	rows, err := d.Pool.Query(ctx, `SELECT host(host), MIN(hour), SUM(bytes_in + bytes_out) FROM host_hourly GROUP BY host HAVING MIN(hour) >= $1 ORDER BY 2 DESC LIMIT 100`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NewHost{}
	for rows.Next() {
		var n NewHost
		if err := rows.Scan(&n.Host, &n.FirstSeen, &n.Bytes); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// NewDestination is a host contacting an ASN it has not used in the lookback period.
type NewDestination struct {
	Host, Peer  string
	ASN         *string
	ASOrg       *string
	CountryCode *string
	Bytes       int64
	Reasons     []string // why it is interesting: hosting, proxy, listed, vt, iot
	HistoryDays int64
}

// DetectNewDestinations finds (host, peer) pairs in the window whose peer ASN (and IP) never appeared in
// host_peer_daily for that host during the previous `days` days, limited to interesting peers or IoT hosts.
func (d *DB) DetectNewDestinations(ctx context.Context, w Window, locals []string, days, minMal int, minHistoryDays int) ([]NewDestination, error) {
	rows, err := d.Pool.Query(ctx, `
WITH f AS (
  SELECT ip_src, ip_dst, bytes, `+local("ip_src", "$3")+` AS ls, `+local("ip_dst", "$3")+` AS ld
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2
),
cur AS (
  SELECT host, peer, SUM(bytes) bytes FROM (
    SELECT ip_src AS host, ip_dst AS peer, bytes FROM f WHERE ls AND NOT ld
    UNION ALL SELECT ip_dst, ip_src, bytes FROM f WHERE ld AND NOT ls) x GROUP BY 1,2
),
today AS (SELECT (now() AT TIME ZONE 'utc')::date AS d),
hist AS (
  SELECT hp.host, hp.peer, i.asn, hp.day FROM host_peer_daily hp LEFT JOIN ip_info i ON i.ip = hp.peer, today
  WHERE hp.day < today.d AND hp.day >= today.d - $4::int
),
depth AS (SELECT host, COUNT(DISTINCT day) days FROM hist GROUP BY host),
cand AS (
  SELECT c.host, c.peer, c.bytes, i.asn, i.as_org, i.country_code, d.days,
    ARRAY_REMOVE(ARRAY[
      CASE WHEN i.is_hosting THEN 'hosting' END,
      CASE WHEN i.is_proxy THEN 'proxy' END,
      CASE WHEN COALESCE(i.vt_malicious,0) >= $5 THEN 'virustotal' END,
      CASE WHEN EXISTS (SELECT 1 FROM threat_lists t WHERE c.peer <<= t.net) THEN 'listed' END,
      CASE WHEN EXISTS (SELECT 1 FROM ip_reputation r WHERE r.ip = c.peer AND r.flagged) THEN 'reputation' END,
      CASE WHEN EXISTS (SELECT 1 FROM ip_nicknames n WHERE n.ip = c.host AND n.kind = 'iot') THEN 'iot' END
    ], NULL) AS reasons
  FROM cur c JOIN ip_info i ON i.ip = c.peer JOIN depth d ON d.host = c.host
  WHERE d.days >= $6 AND i.asn IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM hist h WHERE h.host = c.host AND (h.peer = c.peer OR h.asn = i.asn))
)
SELECT host(host), host(peer), asn, as_org, country_code, bytes, reasons, days FROM cand
WHERE array_length(reasons, 1) > 0 ORDER BY bytes DESC LIMIT 200`,
		w.Since, w.Until, locals, days, minMal, minHistoryDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NewDestination{}
	for rows.Next() {
		var n NewDestination
		if err := rows.Scan(&n.Host, &n.Peer, &n.ASN, &n.ASOrg, &n.CountryCode, &n.Bytes, &n.Reasons, &n.HistoryDays); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Beacon is a (host, peer) pair with suspiciously regular contacts.
type Beacon struct {
	Host, Peer string
	Contacts   int64
	AvgGapMin  float64
	GapCV      float64
	AvgBytes   float64
	Port       int
	First      time.Time
	Last       time.Time
}

// DetectBeacons finds regular, low-volume contact patterns from local hosts to external peers.
func (d *DB) DetectBeacons(ctx context.Context, w Window, locals []string, exempt []string, minContacts int, minGapMin, maxCV float64) ([]Beacon, error) {
	if exempt == nil {
		exempt = []string{}
	}
	rows, err := d.Pool.Query(ctx, `
WITH m AS (
  SELECT ip_src AS host, ip_dst AS peer, stamp_inserted AS t, SUM(bytes) b, MIN(LEAST(port_src, port_dst)) port
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND ip_proto IN (6, 17)
    AND `+local("ip_src", "$3")+` AND NOT `+local("ip_dst", "$3")+`
    AND LEAST(port_src, port_dst) NOT IN (53, 123, 67, 68, 1900, 5353)
    AND NOT (host(ip_src) = ANY($4))
  GROUP BY 1,2,3
),
g AS (SELECT host, peer, t, b, port, EXTRACT(epoch FROM t - lag(t) OVER (PARTITION BY host, peer ORDER BY t)) / 60 AS gap FROM m),
s AS (
  SELECT host, peer, COUNT(*) n, AVG(gap) avg_gap, stddev_samp(gap) sd_gap, AVG(b) avg_b, stddev_samp(b) sd_b,
         mode() WITHIN GROUP (ORDER BY port) port, MIN(t) first, MAX(t) last
  FROM g GROUP BY 1,2
)
SELECT host(host), host(peer), n, avg_gap, COALESCE(sd_gap / NULLIF(avg_gap, 0), 0), avg_b, port, first, last
FROM s WHERE n >= $5 AND avg_gap >= $6 AND COALESCE(sd_gap / NULLIF(avg_gap, 0), 0) <= $7
  AND (COALESCE(sd_b / NULLIF(avg_b, 0), 0) <= 0.5 OR avg_b < 5000)
ORDER BY n DESC LIMIT 100`, w.Since, w.Until, locals, exempt, minContacts, minGapMin, maxCV)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Beacon{}
	for rows.Next() {
		var b Beacon
		if err := rows.Scan(&b.Host, &b.Peer, &b.Contacts, &b.AvgGapMin, &b.GapCV, &b.AvgBytes, &b.Port, &b.First, &b.Last); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// LongLived is a host<->peer connection active for many hours.
type LongLived struct {
	Host, Peer string
	Port       int
	Hours      int64
	Bytes      int64
	Reasons    []string
}

// DetectLongLived finds (host, peer, port) active in >= minHours distinct hours with a hosting/proxy/VPN peer.
func (d *DB) DetectLongLived(ctx context.Context, w Window, locals []string, exempt []string, minHours int) ([]LongLived, error) {
	if exempt == nil {
		exempt = []string{}
	}
	rows, err := d.Pool.Query(ctx, `
WITH m AS (
  SELECT ip_src AS host, ip_dst AS peer, LEAST(port_src, port_dst) port, date_trunc('hour', stamp_inserted) h, SUM(bytes) b
  FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND ip_proto IN (6, 17)
    AND `+local("ip_src", "$3")+` AND NOT `+local("ip_dst", "$3")+` AND NOT (host(ip_src) = ANY($4))
  GROUP BY 1,2,3,4
),
s AS (SELECT host, peer, port, COUNT(*) hours, SUM(b) bytes FROM m GROUP BY 1,2,3 HAVING COUNT(*) >= $5)
SELECT host(s.host), host(s.peer), s.port, s.hours, s.bytes,
  ARRAY_REMOVE(ARRAY[CASE WHEN i.is_hosting THEN 'hosting' END, CASE WHEN i.is_proxy THEN 'proxy' END], NULL)
FROM s JOIN ip_info i ON i.ip = s.peer WHERE i.is_hosting OR i.is_proxy
ORDER BY s.hours DESC, s.bytes DESC LIMIT 100`, w.Since, w.Until, locals, exempt, minHours)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LongLived{}
	for rows.Next() {
		var l LongLived
		if err := rows.Scan(&l.Host, &l.Peer, &l.Port, &l.Hours, &l.Bytes, &l.Reasons); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Fanout is an IoT-kind host talking to many distinct ASNs.
type Fanout struct {
	Host  string
	Kind  string
	ASNs  int64
	Peers int64
}

// DetectIoTFanout finds hosts of the given kinds contacting >= minASNs distinct ASNs in the window.
func (d *DB) DetectIoTFanout(ctx context.Context, w Window, locals []string, kinds []string, minASNs int) ([]Fanout, error) {
	rows, err := d.Pool.Query(ctx, `
WITH f AS (
  SELECT ip_src AS host, ip_dst AS peer FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND `+local("ip_src", "$3")+` AND NOT `+local("ip_dst", "$3")+`
  UNION SELECT ip_dst, ip_src FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2 AND `+local("ip_dst", "$3")+` AND NOT `+local("ip_src", "$3")+`
)
SELECT host(f.host), n.kind, COUNT(DISTINCT i.asn), COUNT(DISTINCT f.peer)
FROM f JOIN ip_nicknames n ON n.ip = f.host AND n.kind = ANY($4) LEFT JOIN ip_info i ON i.ip = f.peer
GROUP BY 1,2 HAVING COUNT(DISTINCT i.asn) >= $5 ORDER BY 3 DESC LIMIT 100`, w.Since, w.Until, locals, kinds, minASNs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Fanout{}
	for rows.Next() {
		var x Fanout
		if err := rows.Scan(&x.Host, &x.Kind, &x.ASNs, &x.Peers); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
