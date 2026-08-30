package db

import (
	"context"
	"errors"
	"strings"
	"time"
)

// IPNote is one journal entry about an address.
type IPNote struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Body      string    `json:"body"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"created_at"`
}

// MaxNoteLen bounds one note.
const MaxNoteLen = 4000

// ListIPNotes returns an address's notes, newest first (limit <= 0 means all, capped at 500).
func (d *DB) ListIPNotes(ctx context.Context, ip string, limit int) ([]IPNote, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	rows, err := d.Pool.Query(ctx, `SELECT id, host(ip), body, author, created_at FROM ip_notes WHERE ip = $1::inet ORDER BY created_at DESC, id DESC LIMIT $2`, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPNote{}
	for rows.Next() {
		var n IPNote
		if err := rows.Scan(&n.ID, &n.IP, &n.Body, &n.Author, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// AddIPNote appends a note.
func (d *DB) AddIPNote(ctx context.Context, ip, body, author string) (*IPNote, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil, errors.New("note is empty")
	}
	if len(body) > MaxNoteLen {
		return nil, errors.New("note is too long")
	}
	var n IPNote
	err := d.Pool.QueryRow(ctx, `INSERT INTO ip_notes (ip, body, author) VALUES ($1::inet, $2, $3) RETURNING id, host(ip), body, author, created_at`,
		ip, body, strings.TrimSpace(author)).Scan(&n.ID, &n.IP, &n.Body, &n.Author, &n.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// DeleteIPNote removes one note of the given address; false when it does not exist.
func (d *DB) DeleteIPNote(ctx context.Context, ip string, id int64) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM ip_notes WHERE id = $1 AND ip = $2::inet`, id, ip)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
