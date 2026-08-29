package db

import (
	"context"
	"time"
)

// RollupHours recomputes host_hourly for every hour bucket intersecting [from, to) for local hosts.
func (d *DB) RollupHours(ctx context.Context, locals []string, from, to time.Time) (int64, error) {
	from = from.UTC().Truncate(time.Hour)
	to = to.UTC()
	tag, err := d.Pool.Exec(ctx, `
WITH f AS (
  SELECT ip_src, ip_dst, bytes, packets, stamp_inserted, port_src, port_dst,
         `+local("ip_src", "$1")+` AS ls, `+local("ip_dst", "$1")+` AS ld
  FROM acct WHERE stamp_inserted >= $2 AND stamp_inserted < $3
),
sides AS (
  SELECT ip_src AS host, date_trunc('hour', stamp_inserted) AS hour, ip_dst AS peer, LEAST(port_src, port_dst) AS port, 0::bigint AS bytes_in, bytes AS bytes_out, packets FROM f WHERE ls
  UNION ALL
  SELECT ip_dst, date_trunc('hour', stamp_inserted), ip_src, LEAST(port_src, port_dst), bytes, 0, packets FROM f WHERE ld
),
agg AS (
  SELECT host, hour, SUM(bytes_in) AS bin, SUM(bytes_out) AS bout, SUM(packets) AS pkts, COUNT(*) AS flows, COUNT(DISTINCT peer) AS peers, COUNT(DISTINCT port) AS ports
  FROM sides GROUP BY host, hour
)
INSERT INTO host_hourly (host, hour, bytes_in, bytes_out, packets, flows, peers, ports)
SELECT host, hour AT TIME ZONE 'utc', bin, bout, pkts, flows, peers, ports FROM agg
ON CONFLICT (host, hour) DO UPDATE SET bytes_in = EXCLUDED.bytes_in, bytes_out = EXCLUDED.bytes_out,
  packets = EXCLUDED.packets, flows = EXCLUDED.flows, peers = EXCLUDED.peers, ports = EXCLUDED.ports`,
		locals, from, to)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RollupPeerDays adds traffic in [from, to) to host_peer_daily (incremental; call with
// non-overlapping windows).
func (d *DB) RollupPeerDays(ctx context.Context, locals []string, from, to time.Time) (int64, error) {
	tag, err := d.Pool.Exec(ctx, `
WITH f AS (
  SELECT ip_src, ip_dst, bytes, stamp_inserted, `+local("ip_src", "$1")+` AS ls, `+local("ip_dst", "$1")+` AS ld
  FROM acct WHERE stamp_inserted >= $2 AND stamp_inserted < $3
),
pairs AS (
  SELECT ip_src AS host, ip_dst AS peer, stamp_inserted::date AS day, bytes FROM f WHERE ls AND NOT ld
  UNION ALL
  SELECT ip_dst, ip_src, stamp_inserted::date, bytes FROM f WHERE ld AND NOT ls
)
INSERT INTO host_peer_daily (host, peer, day, bytes, flows)
SELECT host, peer, day, SUM(bytes), COUNT(*) FROM pairs GROUP BY host, peer, day
ON CONFLICT (host, peer, day) DO UPDATE SET bytes = host_peer_daily.bytes + EXCLUDED.bytes, flows = host_peer_daily.flows + EXCLUDED.flows`,
		locals, from.UTC(), to.UTC())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PruneRollups deletes old rollup rows and old IDS events.
func (d *DB) PruneRollups(ctx context.Context, hourly, daily, ids time.Duration) error {
	for _, q := range []struct {
		sql string
		d   time.Duration
	}{
		{`DELETE FROM host_hourly WHERE hour < now() - $1::interval`, hourly},
		{`DELETE FROM host_peer_daily WHERE day < (now() - $1::interval)::date`, daily},
		{`DELETE FROM ids_events WHERE ts < now() - $1::interval`, ids},
		{`DELETE FROM alerts WHERE state = 'resolved' AND resolved_at < now() - $1::interval`, daily},
	} {
		if _, err := d.Pool.Exec(ctx, q.sql, q.d.String()); err != nil {
			return err
		}
	}
	return nil
}

// HourlyPoint is a rollup row.
type HourlyPoint struct {
	Hour     time.Time `json:"hour"`
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
	Flows    int64     `json:"flows"`
	Peers    int       `json:"peers"`
}

// HostHourly returns rollups for one host.
func (d *DB) HostHourly(ctx context.Context, ip string, since time.Time) ([]HourlyPoint, error) {
	rows, err := d.Pool.Query(ctx, `SELECT hour, bytes_in, bytes_out, flows, peers FROM host_hourly WHERE host = $1::inet AND hour >= $2 ORDER BY hour`, ip, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HourlyPoint{}
	for rows.Next() {
		var p HourlyPoint
		if err := rows.Scan(&p.Hour, &p.BytesIn, &p.BytesOut, &p.Flows, &p.Peers); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
