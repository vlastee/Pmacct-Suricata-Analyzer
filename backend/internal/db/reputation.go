package db

import (
	"context"
	"encoding/json"
	"time"
)

// Reputation is a generic per-source verdict about an IP.
type Reputation struct {
	Source   string          `json:"source"`
	Status   string          `json:"status"`
	Error    *string         `json:"error"`
	Attempts int             `json:"attempts"`
	LookupAt time.Time       `json:"lookup_at"`
	Score    *int            `json:"score"`
	Flagged  bool            `json:"flagged"`
	Data     json.RawMessage `json:"data"`
}

// UpsertReputation stores a lookup result for one source.
func (d *DB) UpsertReputation(ctx context.Context, ip, source string, r *Reputation) error {
	data := r.Data
	if len(data) == 0 {
		data = []byte("{}")
	}
	_, err := d.Pool.Exec(ctx, `INSERT INTO ip_reputation (ip, source, status, error, attempts, lookup_at, score, flagged, data)
VALUES ($1::inet, $2, $3, $4, 1, now(), $5, $6, $7)
ON CONFLICT (ip, source) DO UPDATE SET status = EXCLUDED.status, error = EXCLUDED.error, attempts = ip_reputation.attempts + 1,
  lookup_at = now(), score = COALESCE(EXCLUDED.score, ip_reputation.score), flagged = EXCLUDED.flagged,
  data = CASE WHEN EXCLUDED.status = 'ok' THEN EXCLUDED.data ELSE ip_reputation.data END`,
		ip, source, r.Status, r.Error, r.Score, r.Flagged, data)
	return err
}

// ReputationFor returns all reputation rows for an IP.
func (d *DB) ReputationFor(ctx context.Context, ip string) ([]Reputation, error) {
	rows, err := d.Pool.Query(ctx, `SELECT source, status, error, attempts, lookup_at, score, flagged, data FROM ip_reputation WHERE ip = $1::inet ORDER BY source`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Reputation{}
	for rows.Next() {
		var r Reputation
		if err := rows.Scan(&r.Source, &r.Status, &r.Error, &r.Attempts, &r.LookupAt, &r.Score, &r.Flagged, &r.Data); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReputationCandidates picks external IPs seen since `since` needing a lookup for `source`:
// never checked first (by traffic), then stale ones, then failed after backoff.
func (d *DB) ReputationCandidates(ctx context.Context, source string, since time.Time, locals []string, refreshAfter time.Duration, limit int) ([]string, error) {
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
SELECT host(seen.ip) FROM seen LEFT JOIN ip_reputation r ON r.ip = seen.ip AND r.source = $5
WHERE r.ip IS NULL
   OR (r.status = 'ok' AND r.lookup_at < now() - $3::interval)
   OR (r.status = 'failed' AND r.lookup_at < now() - (interval '30 minutes' * power(2, LEAST(r.attempts, 6))))
ORDER BY (r.ip IS NULL) DESC, seen.bytes DESC
LIMIT $4`
	rows, err := d.Pool.Query(ctx, q, since, locals, refreshAfter.String(), limit, source)
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

// ReputationUsage counts lookups for a source since UTC midnight / month start.
func (d *DB) ReputationUsage(ctx context.Context, source string) (day, month int64, err error) {
	err = d.Pool.QueryRow(ctx, `SELECT
  COUNT(*) FILTER (WHERE lookup_at >= date_trunc('day', now() AT TIME ZONE 'utc') AT TIME ZONE 'utc'),
  COUNT(*) FILTER (WHERE lookup_at >= date_trunc('month', now() AT TIME ZONE 'utc') AT TIME ZONE 'utc')
FROM ip_reputation WHERE source = $1`, source).Scan(&day, &month)
	return
}

// ReputationStats summarises a source.
type ReputationStats struct {
	Source  string `json:"source"`
	Total   int64  `json:"total"`
	Flagged int64  `json:"flagged"`
	Failed  int64  `json:"failed"`
}

// ReputationStats returns per-source counts.
func (d *DB) ReputationStats(ctx context.Context) ([]ReputationStats, error) {
	rows, err := d.Pool.Query(ctx, `SELECT source, COUNT(*), COUNT(*) FILTER (WHERE flagged), COUNT(*) FILTER (WHERE status='failed') FROM ip_reputation GROUP BY source ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReputationStats{}
	for rows.Next() {
		var s ReputationStats
		if err := rows.Scan(&s.Source, &s.Total, &s.Flagged, &s.Failed); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
