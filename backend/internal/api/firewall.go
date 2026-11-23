package api

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// firewallFilter reads the shared query parameters of the firewall endpoints.
func firewallFilter(r *http.Request) (db.FirewallFilter, string) {
	q := r.URL.Query()
	f := db.FirewallFilter{Iface: strings.TrimSpace(q.Get("iface")), Attempts: q.Get("attempts") == "1" || q.Get("attempts") == "true"}
	if ip := strings.TrimSpace(q.Get("ip")); ip != "" {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return f, "invalid ip"
		}
		f.IP = a.String()
	}
	switch a := q.Get("action"); a {
	case "", "pass", "block", "reject":
		f.Action = a
	default:
		return f, "action must be pass, block or reject"
	}
	if p := q.Get("port"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return f, "invalid port"
		}
		f.Port = n
	}
	if t := q.Get("tracker"); t != "" {
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return f, "invalid tracker"
		}
		f.Tracker = n
	}
	return f, ""
}

func (s *Server) firewallSummary(w http.ResponseWriter, r *http.Request) {
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	f, bad := firewallFilter(r)
	if bad != "" {
		writeErr(w, http.StatusBadRequest, bad)
		return
	}
	sum, err := s.DB.FirewallSummary(r.Context(), win, f, s.Cfg.LocalNetworksCIDR(), autoInterval(win), qInt(r, "limit", 10))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := map[string]any{"summary": sum, "enabled": s.Firewall != nil, "retention_days": s.Cfg.FirewallRetentionDays}
	if s.Firewall != nil {
		out["ingest"] = s.Firewall.Stats()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) firewallEvents(w http.ResponseWriter, r *http.Request) {
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	f, bad := firewallFilter(r)
	if bad != "" {
		writeErr(w, http.StatusBadRequest, bad)
		return
	}
	limit := qInt(r, "limit", 200)
	if limit > 2000 {
		limit = 2000
	}
	items, err := s.DB.FirewallEvents(r.Context(), win, f, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) firewallRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.DB.FirewallRules(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

// setFirewallRule names a rule tracker and marks its blocks expected (or not).
func (s *Server) setFirewallRule(w http.ResponseWriter, r *http.Request) {
	tracker, err := strconv.ParseInt(r.PathValue("tracker"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid tracker")
		return
	}
	var body db.FirewallRuleConf
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := s.DB.SetFirewallRule(r.Context(), tracker, body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.firewallRules(w, r)
}
