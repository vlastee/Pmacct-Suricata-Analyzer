package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// User is an application account.
type User struct {
	ID                 int64      `json:"id"`
	Username           string     `json:"username"`
	IsAdmin            bool       `json:"is_admin"`
	MustChangePassword bool       `json:"must_change_password"`
	Disabled           bool       `json:"disabled"`
	CreatedAt          time.Time  `json:"created_at"`
	LastLogin          *time.Time `json:"last_login"`
	LastLoginIP        *string    `json:"last_login_ip"`
	PasswordHash       string     `json:"-"`
}

const userCols = `id, username, is_admin, must_change_password, disabled, created_at, last_login, host(last_login_ip), password_hash`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.IsAdmin, &u.MustChangePassword, &u.Disabled, &u.CreatedAt, &u.LastLogin, &u.LastLoginIP, &u.PasswordHash); err != nil {
		return nil, err
	}
	return &u, nil
}

// CountUsers returns how many accounts exist.
func (d *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser inserts an account.
func (d *DB) CreateUser(ctx context.Context, username, passwordHash string, isAdmin, mustChange bool) (*User, error) {
	return scanUser(d.Pool.QueryRow(ctx, `INSERT INTO users (username, password_hash, is_admin, must_change_password)
VALUES ($1, $2, $3, $4) RETURNING `+userCols, username, passwordHash, isAdmin, mustChange))
}

// GetUserByName looks up a user by username (nil if absent).
func (d *DB) GetUserByName(ctx context.Context, username string) (*User, error) {
	u, err := scanUser(d.Pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE username = $1`, username))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// GetUser looks up a user by id.
func (d *DB) GetUser(ctx context.Context, id int64) (*User, error) {
	u, err := scanUser(d.Pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// ListUsers returns all accounts, newest first.
func (d *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		u.PasswordHash = ""
		out = append(out, *u)
	}
	return out, rows.Err()
}

// SetPassword updates a user's hash and clears the must-change flag.
func (d *DB) SetPassword(ctx context.Context, id int64, passwordHash string) error {
	_, err := d.Pool.Exec(ctx, `UPDATE users SET password_hash = $2, must_change_password = false WHERE id = $1`, id, passwordHash)
	return err
}

// SetUserDisabled toggles an account.
func (d *DB) SetUserDisabled(ctx context.Context, id int64, disabled bool) error {
	_, err := d.Pool.Exec(ctx, `UPDATE users SET disabled = $2 WHERE id = $1`, id, disabled)
	return err
}

// ResetUserPassword sets a new hash and forces a change on next login.
func (d *DB) ResetUserPassword(ctx context.Context, id int64, passwordHash string) error {
	_, err := d.Pool.Exec(ctx, `UPDATE users SET password_hash = $2, must_change_password = true WHERE id = $1`, id, passwordHash)
	return err
}

// DeleteUser removes an account (and cascades its sessions).
func (d *DB) DeleteUser(ctx context.Context, id int64) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	return tag.RowsAffected() > 0, err
}

// RecordLogin stamps a successful login.
func (d *DB) RecordLogin(ctx context.Context, id int64, ip string) error {
	_, err := d.Pool.Exec(ctx, `UPDATE users SET last_login = now(), last_login_ip = $2::inet WHERE id = $1`, id, nilIfEmpty(ip))
	return err
}

// ---- sessions ----

// CreateSession stores a session token.
func (d *DB) CreateSession(ctx context.Context, token string, userID int64, ttl time.Duration, ip, ua string) error {
	_, err := d.Pool.Exec(ctx, `INSERT INTO sessions (token, user_id, expires_at, ip, user_agent)
VALUES ($1, $2, now() + $3::interval, $4::inet, $5)`, token, userID, ttl.String(), nilIfEmpty(ip), ua)
	return err
}

// SessionUser validates a session token and returns its user (nil if invalid/expired).
func (d *DB) SessionUser(ctx context.Context, token string) (*User, error) {
	u, err := scanUser(d.Pool.QueryRow(ctx, `SELECT `+prefixCols(userCols, "u")+`
FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = $1 AND s.expires_at > now() AND NOT u.disabled`, token))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err == nil {
		_, _ = d.Pool.Exec(ctx, `UPDATE sessions SET last_seen = now() WHERE token = $1`, token)
	}
	return u, err
}

// DeleteSession removes one session (logout).
func (d *DB) DeleteSession(ctx context.Context, token string) error {
	_, err := d.Pool.Exec(ctx, `DELETE FROM sessions WHERE token = $1`, token)
	return err
}

// DeleteUserSessions revokes every session of a user (e.g. after password change).
func (d *DB) DeleteUserSessions(ctx context.Context, userID int64, keep string) error {
	_, err := d.Pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token <> $2`, userID, keep)
	return err
}

// PurgeExpiredSessions removes expired sessions.
func (d *DB) PurgeExpiredSessions(ctx context.Context) error {
	_, err := d.Pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	return err
}

// ---- login attempts / brute force ----

// RecordAttempt logs a login attempt.
func (d *DB) RecordAttempt(ctx context.Context, ip, username string, success bool, reason, ua string) error {
	_, err := d.Pool.Exec(ctx, `INSERT INTO login_attempts (ip, username, success, reason, user_agent)
VALUES ($1::inet, $2, $3, $4, $5)`, nilIfEmpty(ip), nilIfEmpty(username), success, nilIfEmpty(reason), ua)
	return err
}

// RecentFailures counts failed attempts from an IP within the window.
func (d *DB) RecentFailures(ctx context.Context, ip string, window time.Duration) (int, error) {
	if ip == "" {
		return 0, nil
	}
	var n int
	err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM login_attempts WHERE ip = $1::inet AND NOT success AND ts > now() - $2::interval`, ip, window.String()).Scan(&n)
	return n, err
}

// LoginActivity is a filter for the security log.
type LoginActivity struct {
	IP        *string   `json:"ip"`
	Username  *string   `json:"username"`
	Success   bool      `json:"success"`
	Reason    *string   `json:"reason"`
	TS        time.Time `json:"ts"`
	UserAgent *string   `json:"user_agent"`
}

// ListLoginAttempts returns recent attempts, optionally filtered.
func (d *DB) ListLoginAttempts(ctx context.Context, ip, username string, onlyFailures bool, limit int) ([]LoginActivity, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	args := []any{}
	conds := []string{"TRUE"}
	if ip != "" {
		args = append(args, ip)
		conds = append(conds, "ip = $1::inet")
	}
	if username != "" {
		args = append(args, username)
		conds = append(conds, "lower(username) = lower($"+itoa(len(args))+")")
	}
	if onlyFailures {
		conds = append(conds, "NOT success")
	}
	args = append(args, limit)
	rows, err := d.Pool.Query(ctx, `SELECT host(ip), username, success, reason, ts, user_agent FROM login_attempts
WHERE `+joinAnd(conds)+` ORDER BY ts DESC LIMIT $`+itoa(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LoginActivity{}
	for rows.Next() {
		var a LoginActivity
		if err := rows.Scan(&a.IP, &a.Username, &a.Success, &a.Reason, &a.TS, &a.UserAgent); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AttemptStat aggregates failed attempts per IP.
type AttemptStat struct {
	IP       string     `json:"ip"`
	Failures int64      `json:"failures"`
	Success  int64      `json:"successes"`
	LastSeen time.Time  `json:"last_seen"`
	Blocked  bool       `json:"blocked"`
	Until    *time.Time `json:"blocked_until"`
}

// TopAttackers aggregates recent login activity by IP with block status.
func (d *DB) TopAttackers(ctx context.Context, window time.Duration, limit int) ([]AttemptStat, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.Pool.Query(ctx, `
SELECT host(a.ip), COUNT(*) FILTER (WHERE NOT a.success), COUNT(*) FILTER (WHERE a.success), MAX(a.ts),
       bl.net IS NOT NULL, bl.expires_at
FROM login_attempts a
LEFT JOIN ip_access bl ON bl.action = 'deny' AND a.ip <<= bl.net AND (bl.expires_at IS NULL OR bl.expires_at > now())
WHERE a.ts > now() - $1::interval AND a.ip IS NOT NULL
GROUP BY a.ip, bl.net, bl.expires_at ORDER BY 2 DESC, 4 DESC LIMIT $2`, window.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AttemptStat{}
	for rows.Next() {
		var s AttemptStat
		if err := rows.Scan(&s.IP, &s.Failures, &s.Success, &s.LastSeen, &s.Blocked, &s.Until); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---- ip access ----

// IPRule is an allow/deny entry.
type IPRule struct {
	Net       string     `json:"net"`
	Action    string     `json:"action"`
	Source    string     `json:"source"`
	Note      *string    `json:"note"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// IPAccessDecision reports whether an IP is denied (manual vs auto lockout) and whether allow rules exist.
type IPAccessDecision struct {
	DeniedManual bool
	DeniedAuto   bool
	Allowed      bool
	HasAllowList bool
}

// CheckIPAccess evaluates the ip_access table for an address.
func (d *DB) CheckIPAccess(ctx context.Context, ip string) (IPAccessDecision, error) {
	var dec IPAccessDecision
	if ip == "" {
		return dec, nil
	}
	err := d.Pool.QueryRow(ctx, `
SELECT
  EXISTS (SELECT 1 FROM ip_access WHERE action='deny' AND source='manual' AND $1::inet <<= net AND (expires_at IS NULL OR expires_at > now())),
  EXISTS (SELECT 1 FROM ip_access WHERE action='deny' AND source='auto'   AND $1::inet <<= net AND (expires_at IS NULL OR expires_at > now())),
  EXISTS (SELECT 1 FROM ip_access WHERE action='allow' AND $1::inet <<= net),
  EXISTS (SELECT 1 FROM ip_access WHERE action='allow')`, ip).Scan(&dec.DeniedManual, &dec.DeniedAuto, &dec.Allowed, &dec.HasAllowList)
	return dec, err
}

// UpsertIPRule creates or updates an allow/deny entry.
func (d *DB) UpsertIPRule(ctx context.Context, net, action, source string, note *string, expires *time.Time) (*IPRule, error) {
	var r IPRule
	err := d.Pool.QueryRow(ctx, `INSERT INTO ip_access (net, action, source, note, expires_at)
VALUES ($1::cidr, $2, $3, $4, $5)
ON CONFLICT (net) DO UPDATE SET action = EXCLUDED.action, source = EXCLUDED.source, note = EXCLUDED.note, expires_at = EXCLUDED.expires_at, created_at = now()
RETURNING host(net) || '/' || masklen(net), action, source, note, created_at, expires_at`, net, action, source, note, expires).
		Scan(&r.Net, &r.Action, &r.Source, &r.Note, &r.CreatedAt, &r.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// AutoBlock adds a temporary deny for an IP (brute-force lockout); never overrides a manual allow.
func (d *DB) AutoBlock(ctx context.Context, ip string, lockout time.Duration) error {
	_, err := d.Pool.Exec(ctx, `INSERT INTO ip_access (net, action, source, note, expires_at)
SELECT $1::inet, 'deny', 'auto', 'brute-force lockout', now() + $2::interval
WHERE NOT EXISTS (SELECT 1 FROM ip_access a WHERE a.action='allow' AND $1::inet <<= a.net)
ON CONFLICT (net) DO UPDATE SET expires_at = now() + $2::interval
WHERE ip_access.source = 'auto'`, ip, lockout.String())
	return err
}

// DeleteIPRule removes an entry.
func (d *DB) DeleteIPRule(ctx context.Context, net string) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM ip_access WHERE net = $1::cidr`, net)
	return tag.RowsAffected() > 0, err
}

// ListIPRules returns access entries (expired auto ones excluded).
func (d *DB) ListIPRules(ctx context.Context) ([]IPRule, error) {
	rows, err := d.Pool.Query(ctx, `SELECT host(net) || '/' || masklen(net), action, source, note, created_at, expires_at
FROM ip_access WHERE expires_at IS NULL OR expires_at > now() ORDER BY action, created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPRule{}
	for rows.Next() {
		var r IPRule
		if err := rows.Scan(&r.Net, &r.Action, &r.Source, &r.Note, &r.CreatedAt, &r.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PurgeExpiredIPRules removes lapsed auto locks.
func (d *DB) PurgeExpiredIPRules(ctx context.Context) error {
	_, err := d.Pool.Exec(ctx, `DELETE FROM ip_access WHERE expires_at IS NOT NULL AND expires_at < now()`)
	return err
}

// ---- helpers ----

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func joinAnd(conds []string) string {
	out := ""
	for i, c := range conds {
		if i > 0 {
			out += " AND "
		}
		out += c
	}
	return out
}

func prefixCols(cols, alias string) string {
	// userCols with each bare column qualified by alias; host(last_login_ip) handled specially.
	out := ""
	for i, c := range splitComma(cols) {
		if i > 0 {
			out += ", "
		}
		c = trimSpace(c)
		switch {
		case c == "host(last_login_ip)":
			out += "host(" + alias + ".last_login_ip)"
		default:
			out += alias + "." + c
		}
	}
	return out
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	depth := 0
	for _, r := range s {
		switch r {
		case '(':
			depth++
			cur += string(r)
		case ')':
			depth--
			cur += string(r)
		case ',':
			if depth == 0 {
				out = append(out, cur)
				cur = ""
			} else {
				cur += string(r)
			}
		default:
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
