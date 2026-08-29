// Package auth provides password hashing, sessions, brute-force protection, IP access control
// and the HTTP middleware that gates the API.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/deezave/pmacct-analyzer/backend/internal/config"
	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// A fixed bcrypt hash of a random string, compared against when the user is unknown so that the
// timing of a login for a non-existent user matches that of an existing one.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("pmacct-analyzer-timing-guard"), bcrypt.DefaultCost)

// Errors returned by Login.
var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrLockedOut          = errors.New("too many failed attempts; try again later")
	ErrDisabled           = errors.New("account disabled")
)

// Service holds auth dependencies.
type Service struct {
	DB  *db.DB
	Cfg *config.Config
}

// ctxKey is the request-context key for the authenticated user.
type ctxKey struct{}

// UserFrom returns the authenticated user from the request context, if any.
func UserFrom(ctx context.Context) *db.User {
	u, _ := ctx.Value(ctxKey{}).(*db.User)
	return u
}

// HashPassword returns a bcrypt hash.
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

// newToken returns a 256-bit URL-safe random token.
func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ClientIP extracts the client address, honouring X-Forwarded-For only when TrustProxy is set.
func (s *Service) ClientIP(r *http.Request) string {
	if s.Cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return normalizeIP(ip)
			}
		}
		if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
			return normalizeIP(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return normalizeIP(r.RemoteAddr)
	}
	return normalizeIP(host)
}

func normalizeIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

// EnsureAdmin seeds the default admin account when no users exist.
func (s *Service) EnsureAdmin(ctx context.Context) error {
	n, err := s.DB.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := HashPassword(s.Cfg.AuthAdminPassword)
	if err != nil {
		return err
	}
	// Default credentials force a password change on first login.
	mustChange := s.Cfg.AuthAdminPassword == "admin"
	if _, err := s.DB.CreateUser(ctx, s.Cfg.AuthAdminUser, hash, true, mustChange); err != nil {
		return err
	}
	slog.Warn("seeded initial admin account", "username", s.Cfg.AuthAdminUser, "must_change_password", mustChange)
	if mustChange {
		slog.Warn("DEFAULT ADMIN PASSWORD IN USE — you will be forced to change it on first login")
	}
	return nil
}

// LoginResult carries the outcome of a successful login.
type LoginResult struct {
	User  *db.User
	Token string
}

// Login validates credentials with brute-force protection. On success it records a session.
func (s *Service) Login(ctx context.Context, ip, username, password, ua string) (*LoginResult, time.Duration, error) {
	// Brute-force gate: too many recent failures from this IP → lock out and reject.
	if ip != "" {
		fails, err := s.DB.RecentFailures(ctx, ip, s.Cfg.LoginWindow)
		if err != nil {
			return nil, 0, err
		}
		if fails >= s.Cfg.LoginMaxFailures {
			_ = s.DB.AutoBlock(ctx, ip, s.Cfg.LoginLockout)
			_ = s.DB.RecordAttempt(ctx, ip, username, false, "locked_out", ua)
			return nil, s.Cfg.LoginLockout, ErrLockedOut
		}
	}

	user, err := s.DB.GetUserByName(ctx, username)
	if err != nil {
		return nil, 0, err
	}
	// Always run bcrypt to keep timing uniform whether or not the user exists.
	hash := dummyHash
	if user != nil {
		hash = []byte(user.PasswordHash)
	}
	pwErr := bcrypt.CompareHashAndPassword(hash, []byte(password))

	if user == nil || pwErr != nil {
		_ = s.DB.RecordAttempt(ctx, ip, username, false, "bad_credentials", ua)
		s.maybeLock(ctx, ip, username, ua)
		return nil, 0, ErrInvalidCredentials
	}
	if user.Disabled {
		_ = s.DB.RecordAttempt(ctx, ip, username, false, "disabled", ua)
		return nil, 0, ErrDisabled
	}

	token := newToken()
	if err := s.DB.CreateSession(ctx, token, user.ID, s.Cfg.SessionTTL, ip, ua); err != nil {
		return nil, 0, err
	}
	_ = s.DB.RecordAttempt(ctx, ip, username, true, "", ua)
	_ = s.DB.RecordLogin(ctx, user.ID, ip)
	return &LoginResult{User: user, Token: token}, 0, nil
}

// maybeLock auto-blocks the IP when this failure crosses the threshold.
func (s *Service) maybeLock(ctx context.Context, ip, username, ua string) {
	if ip == "" {
		return
	}
	fails, err := s.DB.RecentFailures(ctx, ip, s.Cfg.LoginWindow)
	if err != nil {
		return
	}
	if fails >= s.Cfg.LoginMaxFailures {
		_ = s.DB.AutoBlock(ctx, ip, s.Cfg.LoginLockout)
		slog.Warn("auto-blocked IP after repeated failed logins", "ip", ip, "failures", fails, "lockout", s.Cfg.LoginLockout, "last_user", username)
	}
}

// SetCookie writes the session cookie.
func (s *Service) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.Cfg.CookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.Cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(s.Cfg.SessionTTL.Seconds()),
	})
}

// ClearCookie expires the session cookie.
func (s *Service) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: s.Cfg.CookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.Cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// Token reads the session token from the request.
func (s *Service) Token(r *http.Request) string {
	if c, err := r.Cookie(s.Cfg.CookieName); err == nil {
		return c.Value
	}
	return ""
}

// enforceIPAccess returns false (and writes 403) when the client IP is blocked, or when
// allowlist-only mode is on and the IP is not allowed.
func (s *Service) enforceIPAccess(w http.ResponseWriter, r *http.Request, ip string) bool {
	dec, err := s.DB.CheckIPAccess(r.Context(), ip)
	if err != nil {
		return true // fail open on DB error rather than lock everyone out
	}
	if dec.DeniedManual {
		writeJSONError(w, http.StatusForbidden, "your address is blocked")
		return false
	}
	// An auto (brute-force) lockout blocks the app but still lets the login endpoint through,
	// so the client gets a clear 429 + Retry-After instead of an opaque 403.
	if dec.DeniedAuto && r.URL.Path != "/api/v1/auth/login" {
		writeJSONError(w, http.StatusForbidden, "your address is temporarily blocked after repeated failed logins")
		return false
	}
	if s.Cfg.IPAllowlistOnly && dec.HasAllowList && !dec.Allowed {
		writeJSONError(w, http.StatusForbidden, "your address is not on the allow list")
		return false
	}
	return true
}

// Middleware gates requests: IP access on everything, session on /api/* (except auth/login).
// Static assets and the login endpoint stay reachable so the login page can load.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Cfg.AuthEnabled {
			next.ServeHTTP(w, r)
			return
		}
		ip := s.ClientIP(r)
		if r.URL.Path != "/healthz" && !s.enforceIPAccess(w, r, ip) {
			return
		}
		path := r.URL.Path
		// Public: health, the login endpoint, and everything that is not the API (the SPA shell/assets).
		if path == "/healthz" || path == "/api/v1/auth/login" || !strings.HasPrefix(path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		user, err := s.DB.SessionUser(r.Context(), s.Token(r))
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "auth error")
			return
		}
		if user == nil {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		// While a password change is pending, only allow reading self and changing the password.
		if user.MustChangePassword {
			switch path {
			case "/api/v1/auth/me", "/api/v1/auth/change-password", "/api/v1/auth/logout":
			default:
				w.Header().Set("X-Password-Change-Required", "1")
				writeJSONError(w, http.StatusForbidden, "password change required")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, user)))
	})
}

// RequireAdmin wraps a handler so only admin users may call it.
func (s *Service) RequireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Cfg.AuthEnabled {
			u := UserFrom(r.Context())
			if u == nil || !u.IsAdmin {
				writeJSONError(w, http.StatusForbidden, "admin privileges required")
				return
			}
		}
		h(w, r)
	}
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":` + quote(msg) + `}`))
}

func quote(s string) string {
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b = append(b, '\\', byte(r))
		case '\n':
			b = append(b, '\\', 'n')
		default:
			b = append(b, string(r)...)
		}
	}
	b = append(b, '"')
	return string(b)
}
