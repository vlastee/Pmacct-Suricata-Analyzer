// Package api exposes the HTTP JSON API and serves the built frontend.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/auth"
	"github.com/deezave/pmacct-analyzer/backend/internal/config"
	"github.com/deezave/pmacct-analyzer/backend/internal/db"
	"github.com/deezave/pmacct-analyzer/backend/internal/feeds"
	"github.com/deezave/pmacct-analyzer/backend/internal/notify"
	"github.com/deezave/pmacct-analyzer/backend/internal/rules"
	"github.com/deezave/pmacct-analyzer/backend/internal/scheduler"
	"github.com/deezave/pmacct-analyzer/backend/internal/suricata"
	"github.com/deezave/pmacct-analyzer/backend/internal/tlsca"

	"golang.org/x/crypto/bcrypt"
)

// Server holds dependencies for the handlers.
type Server struct {
	DB       *db.DB
	Cfg      *config.Config
	Worker   *scheduler.Worker
	Rules    *rules.Engine      // nil when rules are disabled
	Feeds    *feeds.Fetcher     // nil when no feeds configured
	Notifier *notify.Dispatcher // nil when no channels configured
	Suricata *suricata.Listener // nil when not listening
	TLS      *tlsca.Manager     // built-in HTTPS identity (nil when disabled or using certificate files)
	Auth     *auth.Service      // nil disables authentication
	Now      func() time.Time
}

// Handler builds the router.
func (s *Server) Handler() http.Handler {
	if s.Now == nil {
		s.Now = time.Now
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /api/v1/tls/info", s.tlsInfo)
	mux.HandleFunc("POST /api/v1/agent/enroll", s.agentEnroll)
	mux.HandleFunc("POST /api/v1/agent/events", s.agentEvents)
	mux.HandleFunc("GET /api/v1/agent/builds", s.agentBuilds)
	mux.HandleFunc("GET /api/v1/agent/download/{target}", s.agentDownload)
	mux.HandleFunc("GET /api/v1/agent/{script}", s.agentInstallScript) // install.sh / install.ps1
	mux.HandleFunc("GET /api/v1/agents", s.adminOnly(s.listAgents))
	mux.HandleFunc("POST /api/v1/agents/enroll-tokens", s.adminOnly(s.createEnrollToken))
	mux.HandleFunc("PUT /api/v1/agents/{id}", s.adminOnly(s.updateAgent))
	mux.HandleFunc("POST /api/v1/agents/{id}/{action}", s.adminOnly(s.agentAdminAction))
	mux.HandleFunc("DELETE /api/v1/agents/{id}", s.adminOnly(s.deleteAgent))
	mux.HandleFunc("GET /api/v1/hosts/{ip}/processes", s.hostProcesses)
	mux.HandleFunc("GET /api/v1/tls/ca", s.tlsCA)
	mux.HandleFunc("GET /api/v1/meta", s.meta)
	mux.HandleFunc("GET /api/v1/overview", s.overview)
	mux.HandleFunc("GET /api/v1/timeseries", s.timeseries)
	mux.HandleFunc("GET /api/v1/protocols", s.protocols)
	mux.HandleFunc("GET /api/v1/ports", s.ports)
	mux.HandleFunc("GET /api/v1/hosts", s.hosts)
	mux.HandleFunc("GET /api/v1/hosts/{ip}", s.hostDetail)
	mux.HandleFunc("GET /api/v1/flows", s.flows)
	mux.HandleFunc("GET /api/v1/groups/{dim}", s.groups)
	mux.HandleFunc("GET /api/v1/ips", s.listIPs)
	mux.HandleFunc("GET /api/v1/ips/{ip}", s.getIP)
	mux.HandleFunc("POST /api/v1/ips/{ip}/refresh", s.refreshIP)
	mux.HandleFunc("GET /api/v1/threats", s.threats)
	mux.HandleFunc("GET /api/v1/nicknames", s.listNicknames)
	mux.HandleFunc("GET /api/v1/nicknames/{ip}", s.getNickname)
	mux.HandleFunc("PUT /api/v1/nicknames/{ip}", s.setNickname)
	mux.HandleFunc("DELETE /api/v1/nicknames/{ip}", s.deleteNickname)
	mux.HandleFunc("GET /api/v1/exclusions", s.listExclusions)
	mux.HandleFunc("GET /api/v1/exclusions/match", s.matchExclusion)
	mux.HandleFunc("POST /api/v1/exclusions", s.adminOnly(s.addExclusion))
	mux.HandleFunc("DELETE /api/v1/exclusions/{id}", s.adminOnly(s.deleteExclusion))
	mux.HandleFunc("GET /api/v1/enrichment/status", s.enrichmentStatus)
	mux.HandleFunc("POST /api/v1/enrichment/run", s.enrichmentRun)
	mux.HandleFunc("GET /api/v1/alerts", s.listAlerts)
	mux.HandleFunc("GET /api/v1/alerts/summary", s.alertSummary)
	mux.HandleFunc("POST /api/v1/alerts/resolve", s.resolveAlerts)
	mux.HandleFunc("DELETE /api/v1/alerts/resolved", s.adminOnly(s.deleteResolvedAlerts))
	mux.HandleFunc("GET /api/v1/alerts/settings", s.alertSettings)
	mux.HandleFunc("PUT /api/v1/alerts/settings", s.adminOnly(s.setAlertSettings))
	mux.HandleFunc("DELETE /api/v1/alerts/{id}", s.adminOnly(s.deleteAlert))
	mux.HandleFunc("POST /api/v1/alerts/{id}/{action}", s.alertAction)
	mux.HandleFunc("GET /api/v1/rules", s.listRules)
	mux.HandleFunc("PUT /api/v1/rules/{name}", s.updateRule)
	mux.HandleFunc("POST /api/v1/rules/{name}/run", s.runRule)
	mux.HandleFunc("POST /api/v1/rules/custom", s.adminOnly(s.createCustomRule))
	mux.HandleFunc("POST /api/v1/rules/custom/preview", s.adminOnly(s.previewCustomRule))
	mux.HandleFunc("PUT /api/v1/rules/custom/{name}", s.adminOnly(s.updateCustomRule))
	mux.HandleFunc("DELETE /api/v1/rules/custom/{name}", s.adminOnly(s.deleteCustomRule))
	mux.HandleFunc("GET /api/v1/ids/events", s.idsEvents)
	mux.HandleFunc("GET /api/v1/ids/events/{id}", s.idsEvent)
	mux.HandleFunc("GET /api/v1/ids/summary", s.idsSummary)
	mux.HandleFunc("GET /api/v1/ips/{ip}/names", s.ipNames)
	mux.HandleFunc("GET /api/v1/ips/{ip}/notes", s.listIPNotes)
	mux.HandleFunc("POST /api/v1/ips/{ip}/notes", s.addIPNote)
	mux.HandleFunc("DELETE /api/v1/ips/{ip}/notes/{id}", s.deleteIPNote)
	mux.HandleFunc("GET /api/v1/system/status", s.systemStatus)
	mux.HandleFunc("POST /api/v1/notify/test", s.notifyTest)
	mux.HandleFunc("PUT /api/v1/notify/settings", s.adminOnly(s.notifySettings))
	mux.HandleFunc("GET /api/v1/kinds", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"items": db.DeviceKinds})
	})
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/logout", s.logout)
	mux.HandleFunc("GET /api/v1/auth/me", s.me)
	mux.HandleFunc("POST /api/v1/auth/change-password", s.changePassword)
	mux.HandleFunc("GET /api/v1/auth/users", s.adminOnly(s.listUsers))
	mux.HandleFunc("POST /api/v1/auth/users", s.adminOnly(s.createUser))
	mux.HandleFunc("POST /api/v1/auth/users/{id}/{action}", s.adminOnly(s.userAction))
	mux.HandleFunc("DELETE /api/v1/auth/users/{id}", s.adminOnly(s.deleteUser))
	mux.HandleFunc("GET /api/v1/security/activity", s.adminOnly(s.securityActivity))
	mux.HandleFunc("GET /api/v1/security/attackers", s.adminOnly(s.securityAttackers))
	mux.HandleFunc("GET /api/v1/security/ip-access", s.adminOnly(s.listIPRules))
	mux.HandleFunc("POST /api/v1/security/ip-access", s.adminOnly(s.addIPRule))
	mux.HandleFunc("DELETE /api/v1/security/ip-access", s.adminOnly(s.deleteIPRule))
	mux.Handle("/", s.static())
	var h http.Handler = mux
	if s.Auth != nil {
		h = s.Auth.Middleware(h)
	}
	return logging(h)
}

// adminOnly wraps a handler with the admin guard (pass-through when auth is disabled).
func (s *Server) adminOnly(h http.HandlerFunc) http.HandlerFunc {
	if s.Auth == nil {
		return h
	}
	return s.Auth.RequireAdmin(h)
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			slog.Debug("request", "method", r.Method, "path", r.URL.RequestURI(), "dur", time.Since(start))
		}
	})
}

// static serves the SPA from StaticDir with index.html fallback.
func (s *Server) static() http.Handler {
	dir := s.Cfg.StaticDir
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		p := filepath.Join(dir, filepath.Clean("/"+r.URL.Path))
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			if strings.HasPrefix(r.URL.Path, "/assets/") {
				// Vite emits content-hashed filenames: safe to cache forever.
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			fs.ServeHTTP(w, r)
			return
		}
		idx := filepath.Join(dir, "index.html")
		if _, err := os.Stat(idx); err != nil {
			writeErr(w, http.StatusNotFound, "frontend not built (STATIC_DIR="+dir+")")
			return
		}
		// Always revalidate the SPA shell so a redeploy is picked up immediately.
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, idx)
	})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	slog.Error("handler error", "err", err)
	writeErr(w, http.StatusInternalServerError, err.Error())
}

// window parses since/until. since accepts RFC3339 or a relative duration like "24h".
func (s *Server) window(r *http.Request) (db.Window, error) {
	now := s.Now().UTC()
	q := r.URL.Query()
	until := now
	if v := q.Get("until"); v != "" {
		t, err := parseTime(v, now)
		if err != nil {
			return db.Window{}, errors.New("bad until: " + err.Error())
		}
		until = t
	}
	since := until.Add(-24 * time.Hour)
	if v := q.Get("since"); v != "" {
		t, err := parseTime(v, until)
		if err != nil {
			return db.Window{}, errors.New("bad since: " + err.Error())
		}
		since = t
	}
	if !since.Before(until) {
		return db.Window{}, errors.New("since must be before until")
	}
	return db.Window{Since: since, Until: until}, nil
}

func parseTime(v string, ref time.Time) (time.Time, error) {
	if strings.HasPrefix(v, "-") || strings.HasPrefix(v, "+") {
		v = v[1:]
	}
	if d, err := time.ParseDuration(v); err == nil {
		return ref.Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Time{}, errors.New("expected RFC3339, unix seconds or duration (e.g. 24h)")
}

func qInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func parseIP(w http.ResponseWriter, raw string) (string, bool) {
	a, err := netip.ParseAddr(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid ip address")
		return "", false
	}
	return a.Unmap().String(), true
}

// autoInterval picks a bucket size giving ~200 points for the window.
func autoInterval(w db.Window) time.Duration {
	span := w.Until.Sub(w.Since)
	candidates := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour}
	for _, c := range candidates {
		if span/c <= 300 {
			return c
		}
	}
	return 24 * time.Hour
}

// ---- handlers ----

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.DB.Pool.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "db": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) meta(w http.ResponseWriter, r *http.Request) {
	min, max, err := s.DB.DataRange(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"local_networks": s.Cfg.LocalNetworksCIDR(),
		"data_from":      min,
		"data_to":        max,
		"enrichment":     s.Cfg.EnrichEnabled,
		"now":            s.Now().UTC(),
	})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	locals := s.Cfg.LocalNetworksCIDR()
	ctx := r.Context()
	totals, err := s.DB.Overview(ctx, win, locals)
	if err != nil {
		s.fail(w, err)
		return
	}
	interval := autoInterval(win)
	series, err := s.DB.Timeseries(ctx, win, interval, locals, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	protos, err := s.DB.Protocols(ctx, win, 10)
	if err != nil {
		s.fail(w, err)
		return
	}
	ports, err := s.DB.Ports(ctx, win, 10)
	if err != nil {
		s.fail(w, err)
		return
	}
	t := true
	f := false
	topLocal, _, err := s.DB.Hosts(ctx, win, locals, db.HostsOptions{Local: &t, Limit: 10})
	if err != nil {
		s.fail(w, err)
		return
	}
	topExt, _, err := s.DB.Hosts(ctx, win, locals, db.HostsOptions{Local: &f, Limit: 10})
	if err != nil {
		s.fail(w, err)
		return
	}
	countries, err := s.DB.GroupBy(ctx, win, locals, "country", 10)
	if err != nil {
		s.fail(w, err)
		return
	}
	threats, err := s.DB.Threats(ctx, win, locals, 10)
	if err != nil {
		s.fail(w, err)
		return
	}
	alertSummary, err := s.DB.AlertSummary(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window":       map[string]any{"since": win.Since, "until": win.Until, "interval_seconds": int(interval.Seconds())},
		"totals":       totals,
		"timeseries":   series,
		"protocols":    protos,
		"ports":        ports,
		"top_local":    topLocal,
		"top_external": topExt,
		"countries":    countries,
		"threats":      threats,
		"alerts":       alertSummary,
	})
}

func (s *Server) timeseries(w http.ResponseWriter, r *http.Request) {
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	interval := autoInterval(win)
	if v := r.URL.Query().Get("interval"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad interval")
			return
		}
		interval = d
	}
	ip := ""
	if v := r.URL.Query().Get("ip"); v != "" {
		var ok bool
		if ip, ok = parseIP(w, v); !ok {
			return
		}
	}
	series, err := s.DB.Timeseries(r.Context(), win, interval, s.Cfg.LocalNetworksCIDR(), ip)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"interval_seconds": int(interval.Seconds()), "points": series})
}

func (s *Server) protocols(w http.ResponseWriter, r *http.Request) {
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.DB.Protocols(r.Context(), win, qInt(r, "limit", 25))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) ports(w http.ResponseWriter, r *http.Request) {
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.DB.Ports(r.Context(), win, qInt(r, "limit", 25))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) hosts(w http.ResponseWriter, r *http.Request) {
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	q := r.URL.Query()
	o := db.HostsOptions{
		Sort: q.Get("sort"), Asc: q.Get("order") == "asc", Search: q.Get("q"), Country: q.Get("country"), ASN: q.Get("asn"),
		Limit: qInt(r, "limit", 50), Offset: qInt(r, "offset", 0),
	}
	switch q.Get("scope") {
	case "local":
		t := true
		o.Local = &t
	case "external":
		f := false
		o.Local = &f
	}
	items, total, err := s.DB.Hosts(r.Context(), win, s.Cfg.LocalNetworksCIDR(), o)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.attachRisk(r.Context(), items)
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "limit": o.Limit, "offset": o.Offset})
}

func (s *Server) hostDetail(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	locals := s.Cfg.LocalNetworksCIDR()
	peers, err := s.DB.HostPeers(ctx, win, locals, ip, qInt(r, "limit", 100))
	if err != nil {
		s.fail(w, err)
		return
	}
	ports, err := s.DB.HostPorts(ctx, win, ip, 25)
	if err != nil {
		s.fail(w, err)
		return
	}
	interval := autoInterval(win)
	series, err := s.DB.Timeseries(ctx, win, interval, locals, ip)
	if err != nil {
		s.fail(w, err)
		return
	}
	info, err := s.DB.GetIPInfo(ctx, ip)
	if err != nil {
		s.fail(w, err)
		return
	}
	var sum db.HostStat
	sum.IP = ip
	a, _ := netip.ParseAddr(ip)
	sum.Local = s.Cfg.IsLocal(a)
	for _, p := range peers {
		// peers' in/out are from the perspective of the queried host
		sum.BytesIn += p.BytesIn
		sum.BytesOut += p.BytesOut
		sum.Bytes += p.Bytes
		sum.Packets += p.Packets
		sum.Flows += p.Flows
		if sum.FirstSeen.IsZero() || p.FirstSeen.Before(sum.FirstSeen) {
			sum.FirstSeen = p.FirstSeen
		}
		if p.LastSeen.After(sum.LastSeen) {
			sum.LastSeen = p.LastSeen
		}
	}
	sum.Peers = int64(len(peers))
	sum.Info = info
	var kind string
	if nn, err := s.DB.GetNickname(ctx, ip); err != nil {
		s.fail(w, err)
		return
	} else if nn != nil {
		sum.Nickname = &nn.Nickname
		kind = nn.Kind
	}
	if err := s.decorateIP(ctx, ip, &sum); err != nil {
		s.fail(w, err)
		return
	}
	s.attachRisk(ctx, peers)
	alerts, _, err := s.DB.ListAlerts(ctx, db.AlertsOptions{State: "active", Host: ip, Limit: 50})
	if err != nil {
		s.fail(w, err)
		return
	}
	ids, err := s.DB.ListIDSEvents(ctx, db.IDSOptions{Since: win.Since, IP: ip, Limit: 50})
	if err != nil {
		s.fail(w, err)
		return
	}
	hourly, err := s.DB.HostHourly(ctx, ip, s.Now().Add(-7*24*time.Hour))
	if err != nil {
		s.fail(w, err)
		return
	}
	if risks, err := s.DB.HostRisks(ctx); err == nil {
		if rk, ok := risks[ip]; ok {
			sum.Risk = &rk
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host": sum, "kind": kind, "peers": peers, "ports": ports, "timeseries": series, "alerts": alerts, "ids_events": ids, "hourly": hourly,
		"window": map[string]any{"since": win.Since, "until": win.Until, "interval_seconds": int(interval.Seconds())},
	})
}

func (s *Server) flows(w http.ResponseWriter, r *http.Request) {
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	o := db.FlowsOptions{Port: qInt(r, "port", 0), Proto: qInt(r, "proto", 0), Limit: qInt(r, "limit", 200), Offset: qInt(r, "offset", 0)}
	if v := r.URL.Query().Get("ip"); v != "" {
		var ok bool
		if o.IP, ok = parseIP(w, v); !ok {
			return
		}
	}
	items, err := s.DB.Flows(r.Context(), win, o)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "limit": o.Limit, "offset": o.Offset})
}

func (s *Server) groups(w http.ResponseWriter, r *http.Request) {
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	items, err := s.DB.GroupBy(r.Context(), win, s.Cfg.LocalNetworksCIDR(), r.PathValue("dim"), qInt(r, "limit", 25))
	if err != nil {
		if strings.HasPrefix(err.Error(), "unknown dimension") {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) listIPs(w http.ResponseWriter, r *http.Request) {
	items, err := s.DB.ListIPInfo(r.Context(), r.URL.Query().Get("q"), qInt(r, "limit", 100), qInt(r, "offset", 0))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getIP(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	info, err := s.DB.GetIPInfo(r.Context(), ip)
	if err != nil {
		s.fail(w, err)
		return
	}
	if info == nil {
		writeErr(w, http.StatusNotFound, "no enrichment data for "+ip)
		return
	}
	if err := s.decorateInfo(r.Context(), info); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// decorateInfo adds names, reputation rows and threat lists to a single-IP record.
func (s *Server) decorateInfo(ctx context.Context, info *db.IPInfo) error {
	var err error
	if info.Names, err = s.DB.IPNames(ctx, info.IP, 20); err != nil {
		return err
	}
	if info.Reputation, err = s.DB.ReputationFor(ctx, info.IP); err != nil {
		return err
	}
	if info.Lists, err = s.DB.ThreatListsFor(ctx, info.IP); err != nil {
		return err
	}
	return nil
}

// decorateIP fills names on a host summary and decorates its info when present.
func (s *Server) decorateIP(ctx context.Context, ip string, h *db.HostStat) error {
	names, err := s.DB.IPNames(ctx, ip, 5)
	if err != nil {
		return err
	}
	h.Names = []string{}
	for _, n := range names {
		h.Names = append(h.Names, n.Name)
	}
	if h.Info != nil {
		return s.decorateInfo(ctx, h.Info)
	}
	if !h.Local {
		lists, err := s.DB.ThreatListsFor(ctx, ip)
		if err != nil {
			return err
		}
		if len(lists) > 0 {
			h.Info = &db.IPInfo{IP: ip, Status: "pending", Lists: lists}
		}
	}
	return nil
}

// attachRisk merges risk scores into host rows.
func (s *Server) attachRisk(ctx context.Context, items []db.HostStat) {
	risks, err := s.DB.HostRisks(ctx)
	if err != nil {
		return
	}
	for i := range items {
		if r, ok := risks[items[i].IP]; ok {
			rr := r
			items[i].Risk = &rr
		}
	}
}

func (s *Server) refreshIP(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	if s.Worker == nil {
		writeErr(w, http.StatusServiceUnavailable, "enrichment disabled")
		return
	}
	a, _ := netip.ParseAddr(ip)
	if s.Cfg.IsLocal(a) {
		writeErr(w, http.StatusBadRequest, "refusing to enrich a local address")
		return
	}
	s.Worker.LookupAndStore(r.Context(), ip)
	if s.Worker.VT != nil {
		if _, quota := s.Worker.LookupVT(r.Context(), ip); quota {
			w.Header().Set("X-VT-Quota", "exceeded")
		}
	}
	info, err := s.DB.GetIPInfo(r.Context(), ip)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) threats(w http.ResponseWriter, r *http.Request) {
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	items, err := s.DB.Threats(r.Context(), win, s.Cfg.LocalNetworksCIDR(), qInt(r, "limit", 100))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) listNicknames(w http.ResponseWriter, r *http.Request) {
	items, err := s.DB.ListNicknames(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getNickname(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	n, err := s.DB.GetNickname(r.Context(), ip)
	if err != nil {
		s.fail(w, err)
		return
	}
	if n == nil {
		writeErr(w, http.StatusNotFound, "no nickname for "+ip)
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func (s *Server) setNickname(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	var body struct {
		Nickname string  `json:"nickname"`
		Note     *string `json:"note"`
		Kind     string  `json:"kind"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	body.Nickname = strings.TrimSpace(body.Nickname)
	if body.Nickname == "" || len(body.Nickname) > 100 {
		writeErr(w, http.StatusBadRequest, "nickname must be 1-100 characters")
		return
	}
	if body.Note != nil {
		t := strings.TrimSpace(*body.Note)
		if t == "" {
			body.Note = nil
		} else {
			if len(t) > 2000 {
				writeErr(w, http.StatusBadRequest, "note too long")
				return
			}
			body.Note = &t
		}
	}
	if body.Kind != "" && !slices.Contains(db.DeviceKinds, body.Kind) {
		writeErr(w, http.StatusBadRequest, "kind must be one of "+strings.Join(db.DeviceKinds, ", "))
		return
	}
	n, err := s.DB.SetNickname(r.Context(), ip, body.Nickname, body.Note, body.Kind)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func (s *Server) deleteNickname(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	deleted, err := s.DB.DeleteNickname(r.Context(), ip)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !deleted {
		writeErr(w, http.StatusNotFound, "no nickname for "+ip)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) enrichmentStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.DB.EnrichmentStatus(r.Context(), s.Cfg.EnrichRefreshAfter, s.Cfg.VTRefreshAfter)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := map[string]any{"enabled": s.Cfg.EnrichEnabled, "table": st}
	if s.Worker != nil {
		out["lanes"] = s.Worker.Stats(r.Context())
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) enrichmentRun(w http.ResponseWriter, r *http.Request) {
	if s.Worker == nil {
		writeErr(w, http.StatusServiceUnavailable, "enrichment disabled")
		return
	}
	if r.URL.Query().Get("wait") == "1" {
		n := s.Worker.RunOnce(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"processed": n})
		return
	}
	s.Worker.Kick()
	writeJSON(w, http.StatusAccepted, map[string]any{"queued": true})
}

// ---- alerts ----

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	o := db.AlertsOptions{State: q.Get("state"), Severity: q.Get("severity"), Rule: q.Get("rule"), Limit: qInt(r, "limit", 100), Offset: qInt(r, "offset", 0)}
	if o.State == "" {
		o.State = "active"
	}
	if o.State == "all" {
		o.State = ""
	}
	if v := q.Get("host"); v != "" {
		var ok bool
		if o.Host, ok = parseIP(w, v); !ok {
			return
		}
	}
	if v := q.Get("since"); v != "" {
		t, err := parseTime(v, s.Now().UTC())
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad since")
			return
		}
		o.Since = t
	}
	items, total, err := s.DB.ListAlerts(r.Context(), o)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.annotateExclusions(r.Context(), items); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "limit": o.Limit, "offset": o.Offset})
}

func (s *Server) alertSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.DB.AlertSummary(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) alertAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	state := map[string]string{"ack": "acked", "resolve": "resolved", "reopen": "open"}[r.PathValue("action")]
	if state == "" {
		writeErr(w, http.StatusBadRequest, "action must be ack, resolve or reopen")
		return
	}
	ok, err := s.DB.SetAlertState(r.Context(), id, state)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok && state == "open" {
		var conflict int64
		ok, conflict, err = s.DB.ReopenAlert(r.Context(), id)
		if err != nil {
			s.fail(w, err)
			return
		}
		if conflict > 0 {
			writeErr(w, http.StatusConflict, fmt.Sprintf("cannot reopen: alert #%d is already open for the same finding", conflict))
			return
		}
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "alert not found or transition not allowed")
		return
	}
	a, err := s.DB.GetAlert(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) resolveAlerts(w http.ResponseWriter, r *http.Request) {
	host := ""
	if v := r.URL.Query().Get("host"); v != "" {
		var ok bool
		if host, ok = parseIP(w, v); !ok {
			return
		}
	}
	n, err := s.DB.ResolveAlerts(r.Context(), r.URL.Query().Get("rule"), host)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resolved": n})
}

// alertSettings returns the retention configuration.
func (s *Server) alertSettings(w http.ResponseWriter, r *http.Request) {
	ret, err := s.DB.GetAlertRetention(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ret)
}

// setAlertSettings stores the retention configuration and applies the deletion part right away,
// reporting what it removed so the change is visible immediately.
func (s *Server) setAlertSettings(w http.ResponseWriter, r *http.Request) {
	var ret db.AlertRetention
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&ret); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := ret.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.SetAlertRetention(r.Context(), ret); err != nil {
		s.fail(w, err)
		return
	}
	deleted, err := s.DB.PruneResolvedAlerts(r.Context(), ret)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": ret, "deleted": deleted})
}

// deleteResolvedAlerts permanently removes resolved alerts matching the page's filters.
func (s *Server) deleteResolvedAlerts(w http.ResponseWriter, r *http.Request) {
	host := ""
	if v := r.URL.Query().Get("host"); v != "" {
		var ok bool
		if host, ok = parseIP(w, v); !ok {
			return
		}
	}
	sev := r.URL.Query().Get("severity")
	if sev != "" && db.SeverityRank(sev) == 0 {
		writeErr(w, http.StatusBadRequest, "invalid severity")
		return
	}
	n, err := s.DB.DeleteResolvedAlerts(r.Context(), r.URL.Query().Get("rule"), host, sev)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}

// deleteAlert permanently removes one resolved alert (409 while it is still open/acked).
func (s *Server) deleteAlert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	deleted, existed, err := s.DB.DeleteAlert(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !existed {
		writeErr(w, http.StatusNotFound, "alert not found")
		return
	}
	if !deleted {
		writeErr(w, http.StatusConflict, "only resolved alerts can be deleted — resolve it first")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// ---- rules ----

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "items": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "interval": s.Cfg.RulesInterval.String(), "items": s.Rules.Infos()})
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeErr(w, http.StatusServiceUnavailable, "rules engine disabled")
		return
	}
	var rc rules.RuleConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&rc); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := s.Rules.UpdateConfig(r.Context(), r.PathValue("name"), rc); err != nil {
		s.ruleErr(w, err)
		return
	}
	for _, info := range s.Rules.Infos() {
		if info.Name == r.PathValue("name") {
			writeJSON(w, http.StatusOK, info)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "rule not found")
}

func (s *Server) runRule(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeErr(w, http.StatusServiceUnavailable, "rules engine disabled")
		return
	}
	if r.URL.Query().Get("dry") == "1" {
		findings, err := s.Rules.Preview(r.Context(), r.PathValue("name"))
		if err != nil {
			s.ruleErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
		return
	}
	raised, err := s.Rules.RunRule(r.Context(), r.PathValue("name"), true)
	if err != nil {
		s.ruleErr(w, err)
		return
	}
	if raised == nil {
		raised = []db.Alert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"raised": raised})
}

// ---- IDS ----

// ruleErr maps rules-engine errors to HTTP statuses.
func (s *Server) ruleErr(w http.ResponseWriter, err error) {
	var ve *rules.ValidationError
	switch {
	case errors.Is(err, rules.ErrUnknownRule):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.As(err, &ve):
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		s.fail(w, err)
	}
}

func (s *Server) decodeCustomSpec(w http.ResponseWriter, r *http.Request) (rules.CustomSpec, bool) {
	var spec rules.CustomSpec
	if s.Rules == nil {
		writeErr(w, http.StatusServiceUnavailable, "rules engine disabled")
		return spec, false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&spec); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return spec, false
	}
	return spec, true
}

func (s *Server) createCustomRule(w http.ResponseWriter, r *http.Request) {
	spec, ok := s.decodeCustomSpec(w, r)
	if !ok {
		return
	}
	info, err := s.Rules.SaveCustom(r.Context(), spec, true)
	if err != nil {
		s.ruleErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (s *Server) updateCustomRule(w http.ResponseWriter, r *http.Request) {
	spec, ok := s.decodeCustomSpec(w, r)
	if !ok {
		return
	}
	spec.Name = r.PathValue("name")
	info, err := s.Rules.SaveCustom(r.Context(), spec, false)
	if err != nil {
		s.ruleErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) deleteCustomRule(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeErr(w, http.StatusServiceUnavailable, "rules engine disabled")
		return
	}
	if err := s.Rules.DeleteCustom(r.Context(), r.PathValue("name")); err != nil {
		s.ruleErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": r.PathValue("name")})
}

// previewCustomRule dry-runs an unsaved definition (the editor's Preview button).
func (s *Server) previewCustomRule(w http.ResponseWriter, r *http.Request) {
	spec, ok := s.decodeCustomSpec(w, r)
	if !ok {
		return
	}
	findings, err := s.Rules.PreviewSpec(r.Context(), spec)
	if err != nil {
		s.ruleErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
}

func (s *Server) idsEvents(w http.ResponseWriter, r *http.Request) {
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	o := db.IDSOptions{Since: win.Since, Limit: qInt(r, "limit", 200), Offset: qInt(r, "offset", 0), Raw: r.URL.Query().Get("raw") == "1"}
	if v := r.URL.Query().Get("ip"); v != "" {
		var ok bool
		if o.IP, ok = parseIP(w, v); !ok {
			return
		}
	}
	o.SID = int64(qInt(r, "sid", 0))
	items, err := s.DB.ListIDSEvents(r.Context(), o)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// idsEvent returns one stored IDS event including its raw EVE record (the expand view / deep links).
func (s *Server) idsEvent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid event id")
		return
	}
	ev, err := s.DB.GetIDSEvent(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if ev == nil {
		writeErr(w, http.StatusNotFound, "no such IDS event")
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (s *Server) idsSummary(w http.ResponseWriter, r *http.Request) {
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	items, total, err := s.DB.IDSSummary(r.Context(), win.Since, qInt(r, "limit", 50))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := map[string]any{"items": items, "total": total, "enabled": s.Suricata != nil}
	if s.Suricata != nil {
		out["listener"] = s.Suricata.Stats()
		if last, err := s.DB.LastIDSActivity(r.Context()); err == nil && last != nil {
			out["last_stored_event"] = last
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) ipNames(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	names, err := s.DB.IPNames(r.Context(), ip, qInt(r, "limit", 50))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": names})
}

// ---- system ----

func (s *Server) systemStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{"rules_enabled": s.Rules != nil, "suricata_enabled": s.Suricata != nil, "local_networks": s.Cfg.LocalNetworksCIDR(), "gateways": s.Cfg.Gateways}
	if lists, err := s.DB.ThreatListStats(ctx); err == nil {
		out["threat_lists"] = lists
	}
	if s.Feeds != nil {
		last, results := s.Feeds.Status()
		out["feeds"] = map[string]any{"last_run": last, "results": results, "interval": s.Cfg.ThreatFeedsInterval.String()}
	}
	if s.Notifier != nil {
		out["notifications"] = s.Notifier.Stats()
	} else {
		out["notifications"] = map[string]any{"channels": []string{}}
	}
	if s.Suricata != nil {
		out["suricata"] = s.Suricata.Stats()
	}
	if rep, err := s.DB.ReputationStats(ctx); err == nil {
		out["reputation"] = rep
	}
	if sum, err := s.DB.AlertSummary(ctx); err == nil {
		out["alerts"] = sum
	}
	out["auth_enabled"] = s.Auth != nil
	if s.Auth != nil {
		if attackers, err := s.DB.TopAttackers(ctx, 24*time.Hour, 5); err == nil {
			out["top_attackers"] = attackers
		}
		if rules, err := s.DB.ListIPRules(ctx); err == nil {
			out["ip_rules"] = len(rules)
		}
	}
	if s.Worker != nil {
		out["lanes"] = s.Worker.Stats(ctx)
	}
	writeJSON(w, http.StatusOK, out)
}

// notifySettings changes runtime notification settings (currently the minimum severity).
func (s *Server) notifySettings(w http.ResponseWriter, r *http.Request) {
	if s.Notifier == nil {
		writeErr(w, http.StatusServiceUnavailable, "notifications not configured")
		return
	}
	var body struct {
		MinSeverity string `json:"min_severity"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := s.Notifier.SetMinSeverity(r.Context(), body.MinSeverity); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Notifier.Stats())
}

// ---- built-in HTTPS ----

// tlsInfo describes the HTTPS identity (public: browsers and agents need it before they can
// trust the server). Fingerprints are not secrets.
func (s *Server) tlsInfo(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"enabled": s.Cfg != nil && s.Cfg.TLSListenAddr != "", "internal_ca": s.TLS != nil}
	if s.Cfg != nil && s.Cfg.TLSListenAddr != "" {
		out["addr"] = s.Cfg.TLSListenAddr
		if s.TLS != nil {
			info := s.TLS.Info()
			out["ca_subject"], out["ca_fingerprint_sha256"], out["ca_spki_sha256"], out["ca_not_after"] = info.CASubject, info.CAFingerprint, info.CASPKI, info.CANotAfter
			out["hosts"], out["leaf_not_after"], out["leaf_issued_at"] = info.Hosts, info.LeafNotAfter, info.LeafRenewedAt
			out["url"] = tlsURL(s.Cfg.TLSListenAddr, info.Hosts, r.Host)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// tlsURL builds https://host:port from the listener and the certificate's hosts, preferring
// the name the browser used when it is covered by the certificate.
func tlsURL(addr string, hosts []string, reqHost string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		port = strings.TrimPrefix(addr, ":")
	}
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = h
	}
	pick := ""
	for _, h := range hosts {
		if h == strings.ToLower(reqHost) {
			pick = h
			break
		}
	}
	if pick == "" {
		for _, h := range hosts {
			if h != "localhost" && h != "127.0.0.1" {
				pick = h
				break
			}
		}
	}
	if pick == "" {
		pick = "localhost"
	}
	if strings.Contains(pick, ":") {
		pick = "[" + pick + "]"
	}
	return "https://" + pick + ":" + port
}

// tlsCA serves the internal CA certificate (PEM) for import into browsers, phones and agents.
func (s *Server) tlsCA(w http.ResponseWriter, r *http.Request) {
	if s.TLS == nil {
		writeErr(w, http.StatusNotFound, "built-in TLS is not enabled")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="pmacct-analyzer-ca.pem"`)
	_, _ = w.Write(s.TLS.CAPEM())
}

// ---- per-IP notes ----

func (s *Server) listIPNotes(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	items, err := s.DB.ListIPNotes(r.Context(), ip, qInt(r, "limit", 0))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) addIPNote(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	var body struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	author := ""
	if u := auth.UserFrom(r.Context()); u != nil {
		author = u.Username
	}
	n, err := s.DB.AddIPNote(r.Context(), ip, body.Body, author)
	if err != nil {
		if strings.HasPrefix(err.Error(), "note is") {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, n)
}

func (s *Server) deleteIPNote(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	done, err := s.DB.DeleteIPNote(r.Context(), ip, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !done {
		writeErr(w, http.StatusNotFound, "no such note")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// ---- alert exclusions (global trusted list) ----

// annotateExclusions fills HostExcluded / PeerExcluded so the UI can show status inline.
func (s *Server) annotateExclusions(ctx context.Context, items []db.Alert) error {
	if len(items) == 0 {
		return nil
	}
	set, err := s.DB.LoadExclusions(ctx)
	if err != nil || set.Empty() {
		return err
	}
	names := map[string][]string{}
	if set.HasNames() {
		seen := map[string]bool{}
		var ips []string
		for _, a := range items {
			for _, p := range []*string{a.Host, a.Peer} {
				if p != nil && *p != "" && !seen[*p] {
					seen[*p] = true
					ips = append(ips, *p)
				}
			}
		}
		if names, err = s.DB.NamesForIPs(ctx, ips); err != nil {
			return err
		}
	}
	for i := range items {
		if h := items[i].Host; h != nil {
			items[i].HostExcluded, _ = set.Match(*h, names[*h])
		}
		if p := items[i].Peer; p != nil {
			items[i].PeerExcluded, _ = set.Match(*p, names[*p])
		}
	}
	return nil
}

func (s *Server) listExclusions(w http.ResponseWriter, r *http.Request) {
	items, err := s.DB.ListExclusions(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// addExclusion stores a pattern and resolves the open alerts it now covers.
func (s *Server) addExclusion(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pattern string `json:"pattern"`
		Note    string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	item, err := s.DB.AddExclusion(r.Context(), body.Pattern, body.Note)
	if err != nil {
		if _, _, nerr := db.NormalizeExclusion(body.Pattern); nerr != nil {
			writeErr(w, http.StatusBadRequest, nerr.Error())
			return
		}
		s.fail(w, err)
		return
	}
	resolved, err := s.DB.ResolveExcludedAlerts(r.Context(), db.NewExclusionSet([]db.Exclusion{*item}))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"item": item, "resolved": resolved})
}

func (s *Server) deleteExclusion(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ok, err := s.DB.DeleteExclusion(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "no such exclusion")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// matchExclusion answers "is this address trusted, and by which pattern?" (names included).
func (s *Server) matchExclusion(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.URL.Query().Get("ip"))
	if !ok {
		return
	}
	set, err := s.DB.LoadExclusions(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	var names []string
	if set.HasNames() {
		m, err := s.DB.NamesForIPs(r.Context(), []string{ip})
		if err != nil {
			s.fail(w, err)
			return
		}
		names = m[ip]
	}
	pattern, excluded := set.Match(ip, names)
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "excluded": excluded, "pattern": pattern})
}

func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request) {
	if s.Notifier == nil || len(s.Notifier.Channels) == 0 {
		writeErr(w, http.StatusServiceUnavailable, "no notification channels configured")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": s.Notifier.SendTest(r.Context())})
}

// ---- auth ----

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeErr(w, http.StatusNotImplemented, "authentication is disabled")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	ip := s.Auth.ClientIP(r)
	res, lockout, err := s.Auth.Login(r.Context(), ip, strings.TrimSpace(body.Username), body.Password, r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrLockedOut):
			w.Header().Set("Retry-After", strconv.Itoa(int(lockout.Seconds())))
			writeErr(w, http.StatusTooManyRequests, err.Error())
		case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrDisabled):
			writeErr(w, http.StatusUnauthorized, err.Error())
		default:
			s.fail(w, err)
		}
		return
	}
	s.Auth.SetCookie(w, r, res.Token)
	writeJSON(w, http.StatusOK, map[string]any{"user": res.User, "must_change_password": res.User.MustChangePassword})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if s.Auth != nil {
		_ = s.DB.DeleteSession(r.Context(), s.Auth.Token(r))
		s.Auth.ClearCookie(w, r)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeJSON(w, http.StatusOK, map[string]any{"auth": false})
		return
	}
	u := auth.UserFrom(r.Context())
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"auth": true, "user": u, "must_change_password": u.MustChangePassword})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	full, err := s.DB.GetUser(r.Context(), u.ID)
	if err != nil || full == nil {
		s.fail(w, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(full.PasswordHash), []byte(body.Current)) != nil {
		writeErr(w, http.StatusBadRequest, "current password is incorrect")
		return
	}
	if err := validPassword(body.New); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(body.New)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.DB.SetPassword(r.Context(), u.ID, hash); err != nil {
		s.fail(w, err)
		return
	}
	// Revoke this user's other sessions after a password change.
	_ = s.DB.DeleteUserSessions(r.Context(), u.ID, s.Auth.Token(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func validPassword(pw string) error {
	if len(pw) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if len(pw) > 200 {
		return errors.New("password too long")
	}
	if pw == "admin" {
		return errors.New("choose a different password")
	}
	return nil
}

// ---- user administration ----

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.DB.ListUsers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": users})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if len(body.Username) < 1 || len(body.Username) > 64 {
		writeErr(w, http.StatusBadRequest, "username must be 1-64 characters")
		return
	}
	if err := validPassword(body.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if existing, _ := s.DB.GetUserByName(r.Context(), body.Username); existing != nil {
		writeErr(w, http.StatusConflict, "username already exists")
		return
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		s.fail(w, err)
		return
	}
	u, err := s.DB.CreateUser(r.Context(), body.Username, hash, body.IsAdmin, true)
	if err != nil {
		s.fail(w, err)
		return
	}
	u.PasswordHash = ""
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) userAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ctx := r.Context()
	switch r.PathValue("action") {
	case "disable":
		if me := auth.UserFrom(ctx); me != nil && me.ID == id {
			writeErr(w, http.StatusBadRequest, "cannot disable your own account")
			return
		}
		err = s.DB.SetUserDisabled(ctx, id, true)
	case "enable":
		err = s.DB.SetUserDisabled(ctx, id, false)
	case "reset":
		var body struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body)
		if e := validPassword(body.Password); e != nil {
			writeErr(w, http.StatusBadRequest, e.Error())
			return
		}
		var hash string
		if hash, err = auth.HashPassword(body.Password); err == nil {
			err = s.DB.ResetUserPassword(ctx, id, hash)
		}
	default:
		writeErr(w, http.StatusBadRequest, "action must be disable, enable or reset")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	u, _ := s.DB.GetUser(ctx, id)
	if u != nil {
		u.PasswordHash = ""
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if me := auth.UserFrom(r.Context()); me != nil && me.ID == id {
		writeErr(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}
	n, err := s.DB.CountUsers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if n <= 1 {
		writeErr(w, http.StatusBadRequest, "cannot delete the last account")
		return
	}
	ok, err := s.DB.DeleteUser(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- security (login activity + IP access) ----

func (s *Server) securityActivity(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ip := ""
	if v := q.Get("ip"); v != "" {
		var ok bool
		if ip, ok = parseIP(w, v); !ok {
			return
		}
	}
	items, err := s.DB.ListLoginAttempts(r.Context(), ip, q.Get("user"), q.Get("failures") == "1", qInt(r, "limit", 200))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) securityAttackers(w http.ResponseWriter, r *http.Request) {
	window := 24 * time.Hour
	if v := r.URL.Query().Get("window"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			window = d
		}
	}
	items, err := s.DB.TopAttackers(r.Context(), window, qInt(r, "limit", 50))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) listIPRules(w http.ResponseWriter, r *http.Request) {
	items, err := s.DB.ListIPRules(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "allowlist_only": s.Cfg.IPAllowlistOnly})
}

func (s *Server) addIPRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Net    string `json:"net"`
		Action string `json:"action"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if body.Action != "allow" && body.Action != "deny" {
		writeErr(w, http.StatusBadRequest, "action must be allow or deny")
		return
	}
	net, err := normalizeCIDR(body.Net)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var note *string
	if body.Note != "" {
		note = &body.Note
	}
	rule, err := s.DB.UpsertIPRule(r.Context(), net, body.Action, "manual", note, nil)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) deleteIPRule(w http.ResponseWriter, r *http.Request) {
	net, err := normalizeCIDR(r.URL.Query().Get("net"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ok, err := s.DB.DeleteIPRule(r.Context(), net)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "rule not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// normalizeCIDR accepts an IP or CIDR and returns a canonical prefix string.
func normalizeCIDR(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("net is required")
	}
	if !strings.Contains(raw, "/") {
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return "", errors.New("invalid IP or CIDR")
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()).String(), nil
	}
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return "", errors.New("invalid CIDR")
	}
	return p.Masked().String(), nil
}
