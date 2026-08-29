package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/api"
	"github.com/deezave/pmacct-analyzer/backend/internal/auth"
	"github.com/deezave/pmacct-analyzer/backend/internal/config"
	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

type authEnv struct {
	db  *db.DB
	srv *httptest.Server
	cli *http.Client
	cfg *config.Config
}

func setupAuth(t *testing.T) *authEnv {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	d, err := db.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(d.Close)
	if _, err := d.Pool.Exec(ctx, `DROP TABLE IF EXISTS acct, proto, ip_info, ip_nicknames, alerts, settings, host_hourly, host_peer_daily, threat_lists, ids_events, ip_names, ip_reputation, users, sessions, login_attempts, ip_access, schema_migrations CASCADE`); err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile("fixtures/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool.Exec(ctx, string(schema)); err != nil {
		t.Fatal(err)
	}
	if err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		AuthEnabled: true, AuthAdminUser: "admin", AuthAdminPassword: "admin", SessionTTL: time.Hour, CookieName: "pa_session",
		LoginMaxFailures: 3, LoginWindow: time.Hour, LoginLockout: time.Hour, StaticDir: t.TempDir(),
	}
	if err := os.WriteFile(cfg.StaticDir+"/index.html", []byte("<div id=\"app\"></div>"), 0o644); err != nil {
		t.Fatal(err)
	}
	authSvc := &auth.Service{DB: d, Cfg: cfg}
	if err := authSvc.EnsureAdmin(ctx); err != nil {
		t.Fatal(err)
	}
	s := &api.Server{DB: d, Cfg: cfg, Auth: authSvc}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &authEnv{db: d, srv: srv, cli: &http.Client{Jar: jar}, cfg: cfg}
}

func (e *authEnv) do(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = bytes.NewBufferString(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.cli.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestAuthFlow(t *testing.T) {
	e := setupAuth(t)

	// Unauthenticated API access is rejected; the SPA path is still served.
	if c, _ := e.do(t, "GET", "/api/v1/overview?since=24h", ""); c != 401 {
		t.Errorf("unauthenticated API should be 401, got %d", c)
	}
	if c, _ := e.do(t, "GET", "/", ""); c != 200 {
		t.Errorf("SPA should be reachable without auth, got %d", c)
	}
	if c, _ := e.do(t, "GET", "/healthz", ""); c != 200 {
		t.Errorf("healthz should be public, got %d", c)
	}

	// Wrong password.
	if c, _ := e.do(t, "POST", "/api/v1/auth/login", `{"username":"admin","password":"nope"}`); c != 401 {
		t.Errorf("bad password should be 401, got %d", c)
	}
	// Correct default login → must_change_password true.
	c, body := e.do(t, "POST", "/api/v1/auth/login", `{"username":"admin","password":"admin"}`)
	if c != 200 {
		t.Fatalf("login: %d %s", c, body)
	}
	var lr struct {
		MustChange bool `json:"must_change_password"`
	}
	json.Unmarshal(body, &lr)
	if !lr.MustChange {
		t.Errorf("default admin should require password change: %s", body)
	}

	// While a change is pending, other API calls are 403; me + change-password are allowed.
	if c, _ := e.do(t, "GET", "/api/v1/overview?since=24h", ""); c != 403 {
		t.Errorf("pending change should block API with 403, got %d", c)
	}
	if c, _ := e.do(t, "GET", "/api/v1/auth/me", ""); c != 200 {
		t.Errorf("me should work during pending change, got %d", c)
	}
	// Weak new password rejected.
	if c, _ := e.do(t, "POST", "/api/v1/auth/change-password", `{"current":"admin","new":"short"}`); c != 400 {
		t.Errorf("short password should be 400, got %d", c)
	}
	// Wrong current rejected.
	if c, _ := e.do(t, "POST", "/api/v1/auth/change-password", `{"current":"wrong","new":"newStrongPass1"}`); c != 400 {
		t.Errorf("wrong current should be 400, got %d", c)
	}
	// Successful change.
	if c, _ := e.do(t, "POST", "/api/v1/auth/change-password", `{"current":"admin","new":"newStrongPass1"}`); c != 200 {
		t.Errorf("change-password should succeed, got %d", c)
	}
	// Now full API works.
	if c, _ := e.do(t, "GET", "/api/v1/overview?since=24h", ""); c != 200 {
		t.Errorf("API should work after change, got %d", c)
	}

	// Logout clears the session.
	if c, _ := e.do(t, "POST", "/api/v1/auth/logout", ""); c != 200 {
		t.Errorf("logout: %d", c)
	}
	if c, _ := e.do(t, "GET", "/api/v1/overview?since=24h", ""); c != 401 {
		t.Errorf("after logout API should be 401, got %d", c)
	}
	// New password works, old one does not.
	if c, _ := e.do(t, "POST", "/api/v1/auth/login", `{"username":"admin","password":"admin"}`); c != 401 {
		t.Errorf("old password should fail, got %d", c)
	}
	if c, _ := e.do(t, "POST", "/api/v1/auth/login", `{"username":"admin","password":"newStrongPass1"}`); c != 200 {
		t.Errorf("new password should log in, got %d", c)
	}
}

func TestBruteForceLockout(t *testing.T) {
	e := setupAuth(t)
	// Threshold is 3 failures/hour. The 4th attempt is locked out with 429 even with a correct password.
	for i := 0; i < 3; i++ {
		if c, _ := e.do(t, "POST", "/api/v1/auth/login", `{"username":"admin","password":"bad"}`); c != 401 {
			t.Fatalf("attempt %d expected 401, got %d", i, c)
		}
	}
	c, _ := e.do(t, "POST", "/api/v1/auth/login", `{"username":"admin","password":"admin"}`)
	if c != 429 {
		t.Fatalf("expected lockout 429, got %d", c)
	}
	// The whole app is now blocked for this IP (auto deny).
	if c, _ := e.do(t, "GET", "/", ""); c != 403 {
		t.Errorf("locked-out IP should be blocked from the app (403), got %d", c)
	}
	// It shows up as a blocked attacker.
	var att struct {
		Items []db.AttemptStat `json:"items"`
	}
	rows, err := e.db.TopAttackers(context.Background(), time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	att.Items = rows
	found := false
	for _, a := range att.Items {
		if a.Failures >= 3 && a.Blocked {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a blocked attacker with failures: %+v", att.Items)
	}
	// Clearing the auto-block via the DB (as the admin UI would) restores access.
	if _, err := e.db.Pool.Exec(context.Background(), `DELETE FROM ip_access WHERE source='auto'`); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.do(t, "GET", "/", ""); c != 200 {
		t.Errorf("after clearing block, app should be reachable, got %d", c)
	}
}

func TestIPAccessAndUsers(t *testing.T) {
	e := setupAuth(t)
	// Log in and finish the forced change so we can use admin endpoints.
	e.do(t, "POST", "/api/v1/auth/login", `{"username":"admin","password":"admin"}`)
	e.do(t, "POST", "/api/v1/auth/change-password", `{"current":"admin","new":"adminStrong1"}`)

	// Create a second (non-admin) user.
	if c, b := e.do(t, "POST", "/api/v1/auth/users", `{"username":"bob","password":"bobStrong1","is_admin":false}`); c != 200 {
		t.Fatalf("create user: %d %s", c, b)
	}
	var list struct {
		Items []db.User `json:"items"`
	}
	_, b := e.do(t, "GET", "/api/v1/auth/users", "")
	json.Unmarshal(b, &list)
	if len(list.Items) != 2 {
		t.Errorf("expected 2 users, got %d", len(list.Items))
	}
	var bobID int64
	for _, u := range list.Items {
		if u.Username == "bob" {
			bobID = u.ID
			if !u.MustChangePassword {
				t.Errorf("new user should require password change")
			}
		}
	}

	// bob logs in on a second client, is non-admin → cannot use admin endpoints.
	jar2, _ := cookiejar.New(nil)
	bob := &authEnv{db: e.db, srv: e.srv, cli: &http.Client{Jar: jar2}, cfg: e.cfg}
	bob.do(t, "POST", "/api/v1/auth/login", `{"username":"bob","password":"bobStrong1"}`)
	bob.do(t, "POST", "/api/v1/auth/change-password", `{"current":"bobStrong1","new":"bobNewStrong1"}`)
	if c, _ := bob.do(t, "GET", "/api/v1/auth/users", ""); c != 403 {
		t.Errorf("non-admin should not list users, got %d", c)
	}
	if c, _ := bob.do(t, "GET", "/api/v1/overview?since=24h", ""); c != 200 {
		t.Errorf("non-admin should still use the app, got %d", c)
	}

	// Admin adds an IP deny rule and it takes effect.
	if c, b := e.do(t, "POST", "/api/v1/security/ip-access", `{"net":"203.0.113.0/24","action":"deny","note":"test"}`); c != 200 {
		t.Fatalf("add ip rule: %d %s", c, b)
	}
	var rules struct {
		Items []db.IPRule `json:"items"`
	}
	_, b = e.do(t, "GET", "/api/v1/security/ip-access", "")
	json.Unmarshal(b, &rules)
	if len(rules.Items) != 1 || rules.Items[0].Net != "203.0.113.0/24" || rules.Items[0].Action != "deny" {
		t.Errorf("ip rules: %+v", rules.Items)
	}
	// Delete it.
	if c, _ := e.do(t, "DELETE", "/api/v1/security/ip-access?net=203.0.113.0/24", ""); c != 204 {
		t.Errorf("delete ip rule: %d", c)
	}

	// Login activity is queryable and filterable.
	var act struct {
		Items []db.LoginActivity `json:"items"`
	}
	_, b = e.do(t, "GET", "/api/v1/security/activity?user=bob", "")
	json.Unmarshal(b, &act)
	if len(act.Items) == 0 {
		t.Errorf("expected login activity for bob")
	}
	for _, a := range act.Items {
		if a.Username == nil || *a.Username != "bob" {
			t.Errorf("activity filter leaked non-bob rows: %+v", a)
		}
	}

	// Admin resets bob (forces change), disables, and cannot delete self.
	if c, _ := e.do(t, "POST", "/api/v1/auth/users/"+itoa64(bobID)+"/disable", ""); c != 200 {
		t.Errorf("disable bob: %d", c)
	}
	// bob's existing session is now rejected (disabled user).
	if c, _ := bob.do(t, "GET", "/api/v1/overview?since=24h", ""); c != 401 {
		t.Errorf("disabled user session should be rejected, got %d", c)
	}
	me := list.Items[0] // admin is id-lowest; find self
	for _, u := range list.Items {
		if u.Username == "admin" {
			me = u
		}
	}
	if c, _ := e.do(t, "DELETE", "/api/v1/auth/users/"+itoa64(me.ID), ""); c != 400 {
		t.Errorf("deleting own account should be 400, got %d", c)
	}
	if c, _ := e.do(t, "DELETE", "/api/v1/auth/users/"+itoa64(bobID), ""); c != 204 {
		t.Errorf("delete bob: %d", c)
	}
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
