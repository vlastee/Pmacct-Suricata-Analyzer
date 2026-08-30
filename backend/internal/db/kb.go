package db

import (
	"context"
	"errors"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// KBEntry is a user-defined knowledge-base entry (see explain.Known for the built-in shape).
type KBEntry struct {
	ID          int64     `json:"id"`
	MatchKind   string    `json:"match_kind"` // name | path | hash
	Pattern     string    `json:"pattern"`    // glob (* and ?) for name/path, hex for hash
	Title       string    `json:"title"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Expected    string    `json:"expected"`
	Verify      []string  `json:"verify"`
	Risk        string    `json:"risk"`
	Note        string    `json:"note"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var validRisk = map[string]bool{"": true, "interpreter": true, "lolbin": true, "no-network": true}

// Normalize validates and canonicalises an entry for storage.
func (e *KBEntry) Normalize() error {
	e.MatchKind = strings.ToLower(strings.TrimSpace(e.MatchKind))
	e.Pattern = strings.TrimSpace(e.Pattern)
	e.Title = strings.TrimSpace(e.Title)
	e.Category = strings.ToLower(strings.TrimSpace(e.Category))
	e.Risk = strings.ToLower(strings.TrimSpace(e.Risk))
	if e.Verify == nil {
		e.Verify = []string{}
	}
	switch e.MatchKind {
	case "name", "path":
		e.Pattern = strings.ToLower(strings.ReplaceAll(e.Pattern, `\`, "/"))
		if e.MatchKind == "name" && strings.Contains(e.Pattern, "/") {
			return errors.New("a name pattern must not contain a path; use match_kind \"path\"")
		}
	case "hash":
		e.Pattern = strings.ToLower(e.Pattern)
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(e.Pattern) {
			return errors.New("hash must be a SHA-256 in hex")
		}
	default:
		return errors.New("match_kind must be name, path or hash")
	}
	if e.Pattern == "" || strings.Trim(e.Pattern, "*?/") == "" {
		return errors.New("pattern is empty or matches everything")
	}
	if e.Title == "" {
		return errors.New("title is required")
	}
	if !validRisk[e.Risk] {
		return errors.New("risk must be empty, interpreter, lolbin or no-network")
	}
	return nil
}

// globRe turns a glob with * and ? into an anchored, case-insensitive regexp.
func globRe(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range strings.ToLower(glob) {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// Matches reports whether the entry applies to a program (name, executable path, hashes).
func (e KBEntry) Matches(name, exe string, hashes []string) bool {
	switch e.MatchKind {
	case "hash":
		for _, h := range hashes {
			if strings.EqualFold(h, e.Pattern) {
				return true
			}
		}
		return false
	case "path":
		return exe != "" && globRe(e.Pattern).MatchString(strings.ToLower(strings.ReplaceAll(exe, `\`, "/")))
	default:
		n := strings.ToLower(strings.TrimSpace(name))
		base := strings.ToLower(path.Base(strings.ReplaceAll(exe, `\`, "/")))
		re := globRe(e.Pattern)
		for _, c := range []string{n, strings.TrimSuffix(n, ".exe"), base, strings.TrimSuffix(base, ".exe")} {
			if c != "" && c != "." && re.MatchString(c) {
				return true
			}
		}
		return false
	}
}

// MatchKB picks the most specific matching entry: hash, then path, then name.
func MatchKB(entries []KBEntry, name, exe string, hashes []string) *KBEntry {
	for _, kind := range []string{"hash", "path", "name"} {
		for i := range entries {
			if entries[i].MatchKind == kind && entries[i].Matches(name, exe, hashes) {
				e := entries[i]
				return &e
			}
		}
	}
	return nil
}

const kbCols = `id, match_kind, pattern, title, category, description, expected, verify, risk, note, created_by, created_at, updated_at`

func scanKB(row pgx.Row) (*KBEntry, error) {
	var e KBEntry
	if err := row.Scan(&e.ID, &e.MatchKind, &e.Pattern, &e.Title, &e.Category, &e.Description, &e.Expected, &e.Verify, &e.Risk, &e.Note, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt); err != nil {
		return nil, err
	}
	if e.Verify == nil {
		e.Verify = []string{}
	}
	return &e, nil
}

func (d *DB) ListKB(ctx context.Context) ([]KBEntry, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+kbCols+` FROM kb_entries ORDER BY match_kind, pattern`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KBEntry{}
	for rows.Next() {
		e, err := scanKB(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// UpsertKB inserts or replaces the entry with the same (match_kind, pattern).
func (d *DB) UpsertKB(ctx context.Context, e *KBEntry, by string) (*KBEntry, error) {
	if err := e.Normalize(); err != nil {
		return nil, err
	}
	return scanKB(d.Pool.QueryRow(ctx, `INSERT INTO kb_entries (match_kind, pattern, title, category, description, expected, verify, risk, note, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (match_kind, pattern) DO UPDATE SET title = EXCLUDED.title, category = EXCLUDED.category, description = EXCLUDED.description,
  expected = EXCLUDED.expected, verify = EXCLUDED.verify, risk = EXCLUDED.risk, note = EXCLUDED.note, updated_at = now()
RETURNING `+kbCols, e.MatchKind, e.Pattern, e.Title, e.Category, e.Description, e.Expected, e.Verify, e.Risk, e.Note, by))
}

func (d *DB) DeleteKB(ctx context.Context, id int64) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM kb_entries WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
