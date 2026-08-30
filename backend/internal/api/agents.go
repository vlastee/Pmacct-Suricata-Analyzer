package api

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/auth"
	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// Endpoint agents talk to /api/v1/agent/* with their own bearer token (never a session), and
// only over the TLS listener when one is configured — tokens must not cross the LAN in clear.

const (
	enrollTokenTTL = 24 * time.Hour
	maxAgentBatch  = 20000
	agentBodyLimit = 16 << 20
)

func (s *Server) requireAgentTLS(w http.ResponseWriter, r *http.Request) bool {
	if s.Cfg != nil && s.Cfg.TLSListenAddr != "" && r.TLS == nil {
		writeErr(w, http.StatusForbidden, "agents must use the https listener")
		return false
	}
	return true
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		h = r.RemoteAddr
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return ""
}

// agentAuth resolves the bearer token to an active agent (nil + response written on failure).
func (s *Server) agentAuth(w http.ResponseWriter, r *http.Request) *db.Agent {
	tok := bearer(r)
	if tok == "" {
		writeErr(w, http.StatusUnauthorized, "agent token required")
		return nil
	}
	a, err := s.DB.AgentByToken(r.Context(), tok)
	if err != nil {
		s.fail(w, err)
		return nil
	}
	if a == nil {
		writeErr(w, http.StatusUnauthorized, "unknown or revoked agent token")
		return nil
	}
	return a
}

// ---- agent-facing ----

type enrollRequest struct {
	EnrollToken string   `json:"enroll_token"`
	Hostname    string   `json:"hostname"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	Version     string   `json:"version"`
	IPs         []string `json:"ips"`
}

// agentEnroll exchanges a single-use enrollment token for the agent's own bearer token.
func (s *Server) agentEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.requireAgentTLS(w, r) {
		return
	}
	var req enrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	ips := cleanIPs(req.IPs)
	a, token, err := s.DB.EnrollAgent(r.Context(), req.EnrollToken, trunc(req.Hostname, 200), trunc(req.OS, 40), trunc(req.Arch, 20), trunc(req.Version, 40), ips, remoteIP(r))
	if errors.Is(err, db.ErrEnrollToken) {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"agent_id": a.ID, "agent_token": token, "name": a.Name, "server_time": s.Now().UTC(),
		"local_networks": s.Cfg.LocalNetworksCIDR()})
}

type eventsRequest struct {
	Hostname string            `json:"hostname"`
	Version  string            `json:"version"`
	IPs      []string          `json:"ips"`
	Capture  string            `json:"capture"`
	Dropped  int64             `json:"dropped"`
	Conns    []db.EndpointConn `json:"conns"`
}

// agentEvents ingests a batch of per-minute aggregates; an empty batch is a heartbeat.
func (s *Server) agentEvents(w http.ResponseWriter, r *http.Request) {
	if !s.requireAgentTLS(w, r) {
		return
	}
	a := s.agentAuth(w, r)
	if a == nil {
		return
	}
	var body io.Reader = http.MaxBytesReader(w, r.Body, agentBodyLimit)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad gzip body")
			return
		}
		defer gz.Close()
		body = io.LimitReader(gz, agentBodyLimit)
	}
	var req eventsRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return
	}
	if len(req.Conns) > maxAgentBatch {
		writeErr(w, http.StatusRequestEntityTooLarge, "batch too large")
		return
	}
	now := s.Now().UTC()
	valid := make([]db.EndpointConn, 0, len(req.Conns))
	rejected := 0
	for _, c := range req.Conns {
		if !validConn(&c, now) {
			rejected++
			continue
		}
		valid = append(valid, c)
	}
	n, err := s.DB.InsertEndpointConns(r.Context(), a.ID, valid)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.DB.TouchAgent(r.Context(), a.ID, cleanIPs(req.IPs), trunc(req.Version, 40), trunc(req.Capture, 20), remoteIP(r), n, req.Dropped); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": n, "rejected": rejected, "server_time": now})
}

func validConn(c *db.EndpointConn, now time.Time) bool {
	c.Proto = strings.ToLower(c.Proto)
	if c.Proto != "tcp" && c.Proto != "udp" {
		return false
	}
	h, err := netip.ParseAddr(c.Host)
	if err != nil {
		return false
	}
	d, err := netip.ParseAddr(c.Dst)
	if err != nil || c.DstPort < 0 || c.DstPort > 65535 {
		return false
	}
	c.Host, c.Dst = h.Unmap().String(), d.Unmap().String()
	if c.Minute.IsZero() || c.Minute.After(now.Add(10*time.Minute)) || c.Minute.Before(now.Add(-7*24*time.Hour)) {
		return false
	}
	if c.Count <= 0 {
		c.Count = 1
	}
	if c.Bytes < 0 {
		c.Bytes = 0
	}
	c.Exe, c.Name, c.User, c.SHA256, c.Cmdline = trunc(c.Exe, 512), trunc(c.Name, 128), trunc(c.User, 128), trunc(strings.ToLower(c.SHA256), 64), trunc(c.Cmdline, 2048)
	if c.Name == "" {
		c.Name = baseName(c.Exe)
	}
	return true
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func trunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func cleanIPs(in []string) []string {
	out := []string{}
	for _, s := range in {
		if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
			out = append(out, a.Unmap().String())
		}
		if len(out) >= 16 {
			break
		}
	}
	return out
}

// ---- admin-facing ----

func (s *Server) agentSettings(w http.ResponseWriter, r *http.Request) {
	ret, err := s.DB.GetAgentRetention(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ret)
}

// setAgentSettings stores the retention and applies it right away, reporting what was removed.
func (s *Server) setAgentSettings(w http.ResponseWriter, r *http.Request) {
	var ret db.AgentRetention
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&ret); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := ret.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.SetAgentRetention(r.Context(), ret); err != nil {
		s.fail(w, err)
		return
	}
	conns, agents, err := s.DB.PruneAgentData(r.Context(), ret)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": ret, "deleted_rows": conns, "deleted_agents": agents})
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	items, err := s.DB.ListAgents(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "tls_required": s.Cfg != nil && s.Cfg.TLSListenAddr != ""})
}

// createEnrollToken mints a token and returns everything an agent needs to enroll.
func (s *Server) createEnrollToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body)
	by := ""
	if u := auth.UserFrom(r.Context()); u != nil {
		by = u.Username
	}
	token, exp, err := s.DB.CreateEnrollToken(r.Context(), body.Name, by, enrollTokenTTL)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := map[string]any{"enroll_token": token, "expires_at": exp, "tls_required": s.Cfg.TLSListenAddr != ""}
	if s.TLS != nil {
		info := s.TLS.Info()
		out["server_url"] = tlsURL(s.Cfg.TLSListenAddr, info.Hosts, r.Host)
		out["ca_fingerprint_sha256"] = info.CAFingerprint
		out["ca_spki_sha256"] = info.CASPKI
	} else {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		out["server_url"] = scheme + "://" + r.Host
	}
	writeJSON(w, http.StatusCreated, out)
}

// agentActivity returns what one agent reported in the requested window.
func (s *Server) agentActivity(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	act, err := s.DB.AgentActivityFor(r.Context(), id, win)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, act)
}

func (s *Server) updateAgent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var body struct {
		Name string `json:"name"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	a, err := s.DB.UpdateAgent(r.Context(), id, body.Name, body.Note)
	if err != nil {
		s.fail(w, err)
		return
	}
	if a == nil {
		writeErr(w, http.StatusNotFound, "no such agent")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) agentAdminAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var ok bool
	switch r.PathValue("action") {
	case "revoke":
		ok, err = s.DB.RevokeAgent(r.Context(), id)
	default:
		writeErr(w, http.StatusBadRequest, "action must be revoke")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "no such agent (or already revoked)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) deleteAgent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ok, err := s.DB.DeleteAgent(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "no such agent")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// hostProcesses lists programs seen connecting from a host (agent data) in the window.
func (s *Server) hostProcesses(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(w, r.PathValue("ip"))
	if !ok {
		return
	}
	win, err := s.window(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	items, err := s.DB.HostProcesses(r.Context(), ip, win, qInt(r, "limit", 50))
	if err != nil {
		s.fail(w, err)
		return
	}
	via, err := s.DB.ProcessesForPeers(r.Context(), ip, win)
	if err != nil {
		s.fail(w, err)
		return
	}
	agents, _ := s.DB.CountActiveAgents(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "via": via, "agents": agents})
}
