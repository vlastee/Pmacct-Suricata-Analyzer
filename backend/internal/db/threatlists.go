package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ReplaceThreatList atomically replaces all entries of one list.
func (d *DB) ReplaceThreatList(ctx context.Context, list string, nets []string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM threat_lists WHERE list = $1`, list); err != nil {
		return err
	}
	rows := make([][]any, 0, len(nets))
	for _, n := range nets {
		rows = append(rows, []any{n, list})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"threat_lists"}, []string{"net", "list"}, pgx.CopyFromRows(rows)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ThreatListStats summarises loaded lists.
type ThreatListStat struct {
	List    string    `json:"list"`
	Entries int64     `json:"entries"`
	Updated time.Time `json:"updated"`
}

// ThreatListStats returns entry counts per list.
func (d *DB) ThreatListStats(ctx context.Context) ([]ThreatListStat, error) {
	rows, err := d.Pool.Query(ctx, `SELECT list, COUNT(*), MAX(added_at) FROM threat_lists GROUP BY list ORDER BY list`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatListStat{}
	for rows.Next() {
		var s ThreatListStat
		if err := rows.Scan(&s.List, &s.Entries, &s.Updated); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ThreatListsFor returns the list names an IP appears in.
func (d *DB) ThreatListsFor(ctx context.Context, ip string) ([]string, error) {
	rows, err := d.Pool.Query(ctx, `SELECT DISTINCT list FROM threat_lists WHERE $1::inet <<= net ORDER BY list`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
