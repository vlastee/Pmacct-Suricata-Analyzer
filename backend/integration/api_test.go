// Package integration contains end-to-end tests that run against a real PostgreSQL instance
// (started by scripts/integration-test.sh in a Podman container) and a mock ip-api server.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/api"
	"github.com/deezave/pmacct-analyzer/backend/internal/config"
	"github.com/deezave/pmacct-analyzer/backend/internal/db"
	"github.com/deezave/pmacct-analyzer/backend/internal/enrich"
	"github.com/deezave/pmacct-analyzer/backend/internal/rules"
	"github.com/deezave/pmacct-analyzer/backend/internal/scheduler"
	"github.com/deezave/pmacct-analyzer/backend/internal/suricata"
)

type env struct {
	db     *db.DB
	srv    *httptest.Server
	mock   *mockIPAPI
	vt     *mockVT
	cfg    *config.Config
	worker *scheduler.Worker
	engine *rules.Engine
	ids    *suricata.Listener
}

func TestMain(m *testing.M) {
	if os.Getenv("VERBOSE") == "" {
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	os.Exit(m.Run())
}

func setup(t *testing.T) *env {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; run via scripts/integration-test.sh")
	}
	ctx := context.Background()
	d, err := db.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(d.Close)

	// Fresh state for every test.
	for _, stmt := range []string{"DROP TABLE IF EXISTS acct, proto, ip_info, ip_nicknames, alerts, settings, host_hourly, host_peer_daily, threat_lists, ids_events, ip_names, ip_reputation, users, sessions, login_attempts, ip_access, schema_migrations CASCADE"} {
		if _, err := d.Pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"schema.sql", "data.sql"} {
		b, err := os.ReadFile(filepath.Join("fixtures", f))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Pool.Exec(ctx, string(b)); err != nil {
			t.Fatalf("load %s: %v", f, err)
		}
	}
	if err := d.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Migrations must be idempotent.
	if err := d.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	mock := newMockIPAPI()
	t.Cleanup(mock.Close)
	vtm := newMockVT()
	t.Cleanup(vtm.Close)

	locals, _ := config.ParsePrefixes("192.168.1.0/24,10.0.0.0/24")
	cfg := &config.Config{
		LocalNetworks: locals, EnrichEnabled: true, EnrichInterval: time.Hour, EnrichRefreshAfter: 7 * 24 * time.Hour,
		EnrichBatchSize: 50, EnrichRateLimit: time.Millisecond, EnrichLookbackWindow: 24 * time.Hour,
		HTTPTimeout: 5 * time.Second, StaticDir: t.TempDir(),
		VTAPIKey: "test-key", VTBaseURL: vtm.URL, VTRateLimit: time.Millisecond, VTDailyQuota: 500, VTMonthlyQuota: 15500, VTRefreshAfter: 7 * 24 * time.Hour, VTBatchSize: 100,
	}
	cfg.RulesEnabled = true
	cfg.RulesInterval = time.Hour
	cfg.NotifyRenotifyAfter = time.Hour
	worker := scheduler.New(d, cfg, &enrich.Enricher{Provider: &enrich.IPAPI{BaseURL: mock.URL}, ReverseDNS: false},
		&enrich.VirusTotal{BaseURL: vtm.URL, APIKey: "test-key"})
	engine, err := rules.New(context.Background(), d, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := &suricata.Listener{DB: d, IsLocal: cfg.IsLocal, Sink: engine, Now: time.Now}
	s := &api.Server{DB: d, Cfg: cfg, Worker: worker, Rules: engine, Suricata: ids}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &env{db: d, srv: srv, mock: mock, vt: vtm, cfg: cfg, worker: worker, engine: engine, ids: ids}
}

func (e *env) get(t *testing.T, path string, out any) int {
	t.Helper()
	resp, err := http.Get(e.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(body, out); err != nil {
			t.Fatalf("GET %s: decode %v: %s", path, err, body)
		}
	}
	return resp.StatusCode
}

func (e *env) post(t *testing.T, path string, out any) int {
	t.Helper()
	resp, err := http.Post(e.srv.URL+path, "application/json", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(body, out); err != nil {
			t.Fatalf("POST %s: decode %v: %s", path, err, body)
		}
	}
	return resp.StatusCode
}

func TestHealthAndMeta(t *testing.T) {
	e := setup(t)
	var h map[string]any
	if c := e.get(t, "/healthz", &h); c != 200 || h["status"] != "ok" {
		t.Fatalf("healthz: %d %v", c, h)
	}
	var m struct {
		LocalNetworks []string `json:"local_networks"`
		DataFrom      *string  `json:"data_from"`
	}
	e.get(t, "/api/v1/meta", &m)
	if len(m.LocalNetworks) != 2 || m.LocalNetworks[0] != "192.168.1.0/24" || m.DataFrom == nil {
		t.Errorf("meta: %+v", m)
	}
}

func TestOverviewTotals(t *testing.T) {
	e := setup(t)
	var o struct {
		Totals     db.Totals      `json:"totals"`
		Timeseries []db.Bucket    `json:"timeseries"`
		Protocols  []db.ProtoStat `json:"protocols"`
		Ports      []db.PortStat  `json:"ports"`
		TopLocal   []db.HostStat  `json:"top_local"`
		TopExt     []db.HostStat  `json:"top_external"`
	}
	if c := e.get(t, "/api/v1/overview?since=24h", &o); c != 200 {
		t.Fatalf("status %d", c)
	}
	tt := o.Totals
	if tt.Bytes != 18464 || tt.Flows != 11 || tt.BytesIn != 16030 || tt.BytesOut != 1160 || tt.BytesLocal != 1274 {
		t.Errorf("totals mismatch: %+v", tt)
	}
	if tt.LocalHosts != 2 || tt.ExternalIPs != 3 {
		t.Errorf("host counts: %+v", tt)
	}
	var sum int64
	for _, b := range o.Timeseries {
		sum += b.Bytes
	}
	if sum != 18464 {
		t.Errorf("timeseries sum %d", sum)
	}
	if len(o.Protocols) == 0 || o.Protocols[0].Proto != 6 || o.Protocols[0].Name != "tcp" {
		t.Errorf("protocols: %+v", o.Protocols)
	}
	if len(o.Ports) == 0 || o.Ports[0].Port != 80 || o.Ports[0].Service != "http" {
		t.Errorf("ports: %+v", o.Ports)
	}
	// 192.168.1.20 = 11024 bytes, 192.168.1.10 = 8714 bytes
	if len(o.TopLocal) != 2 || o.TopLocal[0].IP != "192.168.1.20" || !o.TopLocal[0].Local || o.TopLocal[1].IP != "192.168.1.10" {
		t.Errorf("top_local: %+v", o.TopLocal)
	}
	if len(o.TopExt) != 3 || o.TopExt[0].IP != "203.0.113.5" || o.TopExt[0].Local {
		t.Errorf("top_external: %+v", o.TopExt)
	}
	// 192.168.1.10 traffic: out 100+300+10+1234=1644 ; in 2000+5000+30+40=7070 ; peers 8.8.8.8, 1.1.1.1, 192.168.1.20
	h := o.TopLocal[1]
	if h.BytesOut != 1644 || h.BytesIn != 7070 || h.Peers != 3 {
		t.Errorf("192.168.1.10 stats: %+v", h)
	}
}

func TestWindowParsing(t *testing.T) {
	e := setup(t)
	var o struct {
		Totals db.Totals `json:"totals"`
	}
	// 1h window: only the 10/20/30-minute rows = 100+2000+300+5000+50+40 = 7490
	e.get(t, "/api/v1/overview?since=1h", &o)
	if o.Totals.Bytes != 7490 {
		t.Errorf("1h bytes = %d", o.Totals.Bytes)
	}
	// 7 days: includes the 3-day-old 99999 row
	e.get(t, "/api/v1/overview?since=168h", &o)
	if o.Totals.Bytes != 18464+99999 {
		t.Errorf("7d bytes = %d", o.Totals.Bytes)
	}
	if c := e.get(t, "/api/v1/overview?since=nonsense", nil); c != 400 {
		t.Errorf("bad since should be 400, got %d", c)
	}
	until := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if c := e.get(t, "/api/v1/overview?since=1h&until="+until, &o); c != 200 {
		t.Errorf("rfc3339 until: %d", c)
	}
}

func TestHostsFilteringAndDetail(t *testing.T) {
	e := setup(t)
	var hs struct {
		Items []db.HostStat `json:"items"`
		Total int64         `json:"total"`
	}
	e.get(t, "/api/v1/hosts?since=24h&scope=local", &hs)
	if hs.Total != 2 {
		t.Errorf("local total %d", hs.Total)
	}
	e.get(t, "/api/v1/hosts?since=24h&scope=external&sort=flows", &hs)
	if hs.Total != 3 || hs.Items[0].IP != "8.8.8.8" {
		t.Errorf("external by flows: %+v", hs.Items)
	}
	e.get(t, "/api/v1/hosts?since=24h&scope=external&sort=flows&order=asc", &hs)
	if hs.Items[len(hs.Items)-1].IP != "8.8.8.8" {
		t.Errorf("ascending order: %+v", hs.Items)
	}
	e.get(t, "/api/v1/hosts?since=24h&sort=ip&order=asc", &hs)
	if hs.Items[0].IP != "1.1.1.1" || hs.Items[len(hs.Items)-1].IP != "203.0.113.5" {
		t.Errorf("sort by ip: %+v", hs.Items)
	}
	e.get(t, "/api/v1/hosts?since=24h&q=8.8.", &hs)
	if hs.Total != 1 {
		t.Errorf("search total %d", hs.Total)
	}
	e.get(t, "/api/v1/hosts?since=24h&limit=1&offset=1", &hs)
	if len(hs.Items) != 1 || hs.Total != 5 {
		t.Errorf("pagination: %d items / %d total", len(hs.Items), hs.Total)
	}

	var d struct {
		Host  db.HostStat   `json:"host"`
		Peers []db.HostStat `json:"peers"`
		Ports []db.PortStat `json:"ports"`
	}
	if c := e.get(t, "/api/v1/hosts/192.168.1.20?since=24h", &d); c != 200 {
		t.Fatalf("detail: %d", c)
	}
	// 192.168.1.20: out 50+40+700 = 790 ; in 9000+1234 = 10234 ; peers 8.8.8.8, 192.168.1.10, 203.0.113.5
	if d.Host.BytesOut != 790 || d.Host.BytesIn != 10234 || len(d.Peers) != 3 || !d.Host.Local {
		t.Errorf("detail host: %+v peers=%d", d.Host, len(d.Peers))
	}
	if d.Peers[0].IP != "203.0.113.5" || d.Peers[0].BytesIn != 9000 {
		t.Errorf("top peer: %+v", d.Peers[0])
	}
	if c := e.get(t, "/api/v1/hosts/not-an-ip?since=24h", nil); c != 400 {
		t.Errorf("bad ip: %d", c)
	}
}

func TestFlows(t *testing.T) {
	e := setup(t)
	var f struct {
		Items []db.Flow `json:"items"`
	}
	e.get(t, "/api/v1/flows?since=24h&ip=1.1.1.1", &f)
	if len(f.Items) != 2 {
		t.Errorf("flows for 1.1.1.1: %d", len(f.Items))
	}
	e.get(t, "/api/v1/flows?since=24h&port=53&proto=17", &f)
	if len(f.Items) != 3 {
		t.Errorf("dns flows: %d", len(f.Items))
	}
	e.get(t, "/api/v1/flows?since=24h&limit=2", &f)
	if len(f.Items) != 2 || f.Items[0].StampInserted.Before(f.Items[1].StampInserted) {
		t.Errorf("limit/order: %+v", f.Items)
	}
}

func TestEnrichmentWorkerAndGroups(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	var st struct {
		Table db.EnrichmentStatus `json:"table"`
	}
	e.get(t, "/api/v1/enrichment/status", &st)
	if st.Table.Total != 0 {
		t.Fatalf("expected empty ip_info, got %+v", st.Table)
	}

	// Run a pass: 3 external IPs within 24h; 2 succeed on the mock, 203.0.113.5 fails.
	// 198.51.100.9 is older than the lookback and must NOT be looked up.
	n := e.worker.RunGeoOnce(ctx)
	if n != 3 {
		t.Errorf("processed %d candidates, want 3", n)
	}
	if e.mock.calls.Load() != 3 {
		t.Errorf("mock calls %d", e.mock.calls.Load())
	}
	e.get(t, "/api/v1/enrichment/status", &st)
	if st.Table.OK != 2 || st.Table.Failed != 1 || st.Table.Total != 3 {
		t.Errorf("after pass: %+v", st.Table)
	}

	var info db.IPInfo
	if c := e.get(t, "/api/v1/ips/8.8.8.8", &info); c != 200 {
		t.Fatalf("get ip: %d", c)
	}
	if info.ASN == nil || *info.ASN != "AS15169" || *info.CountryCode != "US" || *info.Hostname != "dns.google" || info.Status != "ok" {
		t.Errorf("8.8.8.8 enrichment: %+v", info)
	}
	if c := e.get(t, "/api/v1/ips/203.0.113.5", &info); c != 200 || info.Status != "failed" || info.Error == nil {
		t.Errorf("failed record: %d %+v", c, info)
	}
	if c := e.get(t, "/api/v1/ips/198.51.100.9", nil); c != 404 {
		t.Errorf("stale-window ip should not be enriched: %d", c)
	}

	// A second pass must not re-query fresh records; the failed one is in backoff (10 min).
	before := e.mock.calls.Load()
	if n := e.worker.RunGeoOnce(ctx); n != 0 {
		t.Errorf("second pass processed %d, want 0", n)
	}
	if e.mock.calls.Load() != before {
		t.Errorf("second pass hit the provider")
	}

	// Stale records get refreshed: age one record artificially.
	if _, err := e.db.Pool.Exec(ctx, `UPDATE ip_info SET last_lookup = now() - interval '30 days' WHERE ip = '1.1.1.1'`); err != nil {
		t.Fatal(err)
	}
	if n := e.worker.RunGeoOnce(ctx); n != 1 {
		t.Errorf("stale pass processed %d, want 1", n)
	}
	e.get(t, "/api/v1/ips/1.1.1.1", &info)
	if info.Attempts != 2 || time.Since(*info.LastLookup) > time.Minute {
		t.Errorf("stale refresh: attempts=%d last=%v", info.Attempts, info.LastLookup)
	}

	// Manual refresh endpoint.
	if c := e.post(t, "/api/v1/ips/8.8.8.8/refresh", &info); c != 200 || info.Attempts != 2 {
		t.Errorf("refresh: %d %+v", c, info)
	}
	if c := e.post(t, "/api/v1/ips/192.168.1.10/refresh", nil); c != 400 {
		t.Errorf("refresh local ip should be 400, got %d", c)
	}

	// Hosts now carry enrichment; group by country/asn works.
	var hs struct {
		Items []db.HostStat `json:"items"`
	}
	e.get(t, "/api/v1/hosts?since=24h&scope=external&country=us", &hs)
	if len(hs.Items) != 1 || hs.Items[0].Info == nil || *hs.Items[0].Info.ASOrg != "Google LLC" {
		t.Errorf("country filter: %+v", hs.Items)
	}
	e.get(t, "/api/v1/hosts?since=24h&q=cloudflare", &hs)
	if len(hs.Items) != 1 || hs.Items[0].IP != "1.1.1.1" {
		t.Errorf("org search: %+v", hs.Items)
	}
	var g struct {
		Items []db.GroupStat `json:"items"`
	}
	e.get(t, "/api/v1/groups/country?since=24h", &g)
	// bytes per country: ?? (203.0.113.5) = 9700, AU = 5300, US = 2190
	if len(g.Items) != 3 || g.Items[0].Key != "??" || g.Items[0].Bytes != 9700 || g.Items[1].Key != "AU" || g.Items[1].Bytes != 5300 {
		t.Errorf("groups/country: %+v", g.Items)
	}
	e.get(t, "/api/v1/groups/asn?since=24h", &g)
	if len(g.Items) != 3 || g.Items[1].Label != "Cloudflare, Inc." {
		t.Errorf("groups/asn: %+v", g.Items)
	}
	if c := e.get(t, "/api/v1/groups/bogus?since=24h", nil); c != 400 {
		t.Errorf("bogus dim: %d", c)
	}

	var run map[string]any
	if c := e.post(t, "/api/v1/enrichment/run?wait=1", &run); c != 200 {
		t.Errorf("run endpoint: %d", c)
	}
	var list struct {
		Items []db.IPInfo `json:"items"`
	}
	e.get(t, "/api/v1/ips?q=google", &list)
	if len(list.Items) != 1 {
		t.Errorf("ips search: %d", len(list.Items))
	}
}

func TestVirusTotalLane(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	// Pass 1: all three external IPs seen in the last 24h are unknown -> looked up, biggest traffic first.
	if n := e.worker.RunVTOnce(ctx); n != 3 {
		t.Fatalf("first VT pass attempted %d, want 3", n)
	}
	got := e.vt.requested()
	// traffic: 203.0.113.5=9700, 1.1.1.1=5300, 8.8.8.8=2190
	if len(got) != 3 || got[0] != "203.0.113.5" || got[1] != "1.1.1.1" || got[2] != "8.8.8.8" {
		t.Errorf("VT lookup order (unknown first, by bytes): %v", got)
	}
	// 198.51.100.9 (3 days old) must never be sent to VT: it's outside the daily feed.
	for _, ip := range got {
		if ip == "198.51.100.9" {
			t.Errorf("stale IP was sent to VT")
		}
	}

	var info db.IPInfo
	if c := e.get(t, "/api/v1/ips/203.0.113.5", &info); c != 200 {
		t.Fatalf("get: %d", c)
	}
	if info.VT == nil || *info.VT.Malicious != 7 || *info.VT.Suspicious != 2 || len(info.VT.Tags) != 2 || info.VT.Status != "ok" {
		t.Errorf("VT data: %+v", info.VT)
	}
	// Geo fields from VT fill the gaps of a record that had no geo lookup yet.
	if info.ASN == nil || *info.ASN != "AS64496" || info.Status != "pending" {
		t.Errorf("VT should seed asn on a pending record: %+v", info)
	}

	// Pass 2: nothing is unknown or stale -> zero quota spent.
	before := e.vt.calls.Load()
	if n := e.worker.RunVTOnce(ctx); n != 0 {
		t.Errorf("second VT pass attempted %d, want 0", n)
	}
	if e.vt.calls.Load() != before {
		t.Errorf("second pass consumed quota")
	}

	// Stale-but-still-seen: age 8.8.8.8 -> refreshed. Age 198.51.100.9 too (insert a row) -> still ignored.
	if _, err := e.db.Pool.Exec(ctx, `UPDATE ip_info SET vt_lookup_at = now() - interval '30 days' WHERE ip = '8.8.8.8'`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Pool.Exec(ctx, `INSERT INTO ip_info (ip, vt_status, vt_lookup_at) VALUES ('198.51.100.9', 'ok', now() - interval '30 days')`); err != nil {
		t.Fatal(err)
	}
	if n := e.worker.RunVTOnce(ctx); n != 1 {
		t.Errorf("stale VT pass attempted %d, want 1", n)
	}
	if last := e.vt.requested(); last[len(last)-1] != "8.8.8.8" {
		t.Errorf("stale refresh should target 8.8.8.8, got %v", last)
	}
	e.get(t, "/api/v1/ips/8.8.8.8", &info)
	if info.VT == nil || info.VT.Attempts != 2 {
		t.Errorf("attempts after refresh: %+v", info.VT)
	}

	// Threats endpoint + overview surface the flagged IP with the local hosts that talked to it.
	var th struct {
		Items []db.Threat `json:"items"`
	}
	e.get(t, "/api/v1/threats?since=24h", &th)
	if len(th.Items) != 1 || th.Items[0].IP != "203.0.113.5" || th.Items[0].Malicious != 7 || len(th.Items[0].LocalHosts) != 1 || th.Items[0].LocalHosts[0] != "192.168.1.20" {
		t.Errorf("threats: %+v", th.Items)
	}
	var ov struct {
		Threats []db.Threat `json:"threats"`
	}
	e.get(t, "/api/v1/overview?since=24h", &ov)
	if len(ov.Threats) != 1 {
		t.Errorf("overview threats: %+v", ov.Threats)
	}

	// Status reflects the lane.
	var st struct {
		Table db.EnrichmentStatus            `json:"table"`
		Lanes map[string]scheduler.LaneStats `json:"lanes"`
	}
	e.get(t, "/api/v1/enrichment/status", &st)
	if st.Table.VTDone != 4 || st.Table.VTFlagged != 1 || st.Table.VTUsedToday != 3 {
		t.Errorf("status table: %+v", st.Table)
	}
	if l := st.Lanes["vt"]; !l.Enabled || l.DailyQuota != 500 || l.QuotaUsed != 3 || l.Lookups != 4 {
		t.Errorf("vt lane: %+v", l)
	}
}

func TestVirusTotalQuota(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	// Daily quota already consumed (from the DB, so it survives restarts) -> no lookups at all.
	e.cfg.VTDailyQuota = 2
	if _, err := e.db.Pool.Exec(ctx, `INSERT INTO ip_info (ip, vt_status, vt_lookup_at) VALUES ('192.0.2.1','ok',now()), ('192.0.2.2','ok',now())`); err != nil {
		t.Fatal(err)
	}
	if n := e.worker.RunVTOnce(ctx); n != 0 || e.vt.calls.Load() != 0 {
		t.Errorf("quota exhausted but attempted %d (calls %d)", n, e.vt.calls.Load())
	}
	st := e.worker.Stats(ctx)["vt"]
	if !st.QuotaHit {
		t.Errorf("expected quota_hit: %+v", st)
	}

	// Budget of 1 remaining -> exactly one lookup, and it's the biggest unknown IP.
	e.cfg.VTDailyQuota = 3
	if n := e.worker.RunVTOnce(ctx); n != 1 || e.vt.calls.Load() != 1 {
		t.Errorf("budget 1: attempted %d calls %d", n, e.vt.calls.Load())
	}
	if got := e.vt.requested(); got[0] != "203.0.113.5" {
		t.Errorf("should spend the single lookup on the top unknown IP, got %v", got)
	}

	// Provider-side 429 stops the pass immediately; the IP that hit it is not recorded, so
	// it is retried first next time.
	e.cfg.VTDailyQuota = 500
	e.vt.quotaAt = e.vt.calls.Load() + 1 // allow one more call, then 429
	if n := e.worker.RunVTOnce(ctx); n != 2 {
		t.Errorf("429 pass attempted %d, want 2 (one ok, one 429)", n)
	}
	if !e.worker.Stats(ctx)["vt"].QuotaHit {
		t.Errorf("quota_hit should be set after 429")
	}
	var info db.IPInfo
	if c := e.get(t, "/api/v1/ips/8.8.8.8", &info); c == 200 && info.VT != nil {
		t.Errorf("429'd lookup must not be stored: %+v", info.VT)
	}
	e.vt.quotaAt = 0
	if n := e.worker.RunVTOnce(ctx); n != 1 {
		t.Errorf("retry pass attempted %d, want 1", n)
	}
	if c := e.get(t, "/api/v1/ips/8.8.8.8", &info); c != 200 || info.VT == nil || info.VT.Status != "ok" {
		t.Errorf("retry should store 8.8.8.8: %d %+v", c, info.VT)
	}
}

func TestVirusTotalMonthlyQuota(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	// 2 lookups earlier this month (but not today) + monthly cap of 3 -> exactly 1 lookup allowed
	// even though the daily budget (500) is untouched.
	if _, err := e.db.Pool.Exec(ctx, `INSERT INTO ip_info (ip, vt_status, vt_lookup_at) VALUES
		('192.0.2.1','ok', date_trunc('month', now() AT TIME ZONE 'utc') AT TIME ZONE 'utc' + interval '1 minute'),
		('192.0.2.2','ok', date_trunc('month', now() AT TIME ZONE 'utc') AT TIME ZONE 'utc' + interval '2 minutes')`); err != nil {
		t.Fatal(err)
	}
	e.cfg.VTMonthlyQuota = 3
	if n := e.worker.RunVTOnce(ctx); n != 1 || e.vt.calls.Load() != 1 {
		t.Errorf("monthly budget 1: attempted %d calls %d", n, e.vt.calls.Load())
	}
	st := e.worker.Stats(ctx)["vt"]
	if st.MonthlyQuota != 3 || st.QuotaUsedMonth != 3 {
		t.Errorf("monthly stats: %+v", st)
	}
	if n := e.worker.RunVTOnce(ctx); n != 0 || !e.worker.Stats(ctx)["vt"].QuotaHit {
		t.Errorf("monthly quota should now be exhausted (attempted %d)", n)
	}
}

func TestNicknames(t *testing.T) {
	e := setup(t)
	put := func(ip, body string) (int, db.Nickname) {
		req, _ := http.NewRequest(http.MethodPut, e.srv.URL+"/api/v1/nicknames/"+ip, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var n db.Nickname
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == 200 {
			_ = json.Unmarshal(b, &n)
		}
		return resp.StatusCode, n
	}
	if c, n := put("192.168.1.10", `{"nickname":"NAS","note":"Synology in the closet","kind":"server"}`); c != 200 || n.Nickname != "NAS" || n.Note == nil || n.Kind != "server" {
		t.Fatalf("put local: %d %+v", c, n)
	}
	if c, n := put("8.8.8.8", `{"nickname":"Google DNS"}`); c != 200 || n.Nickname != "Google DNS" || n.Note != nil {
		t.Fatalf("put external: %d %+v", c, n)
	}
	if c, _ := put("192.168.1.10", `{"nickname":"  NAS-01 ","note":"  "}`); c != 200 {
		t.Errorf("update: %d", c)
	}
	if c, _ := put("192.168.1.10", `{"nickname":""}`); c != 400 {
		t.Errorf("empty nickname should be 400, got %d", c)
	}
	if c, _ := put("nope", `{"nickname":"x"}`); c != 400 {
		t.Errorf("bad ip should be 400, got %d", c)
	}
	if c, _ := put("192.168.1.10", `not json`); c != 400 {
		t.Errorf("bad json should be 400, got %d", c)
	}

	var one db.Nickname
	if c := e.get(t, "/api/v1/nicknames/192.168.1.10", &one); c != 200 || one.Nickname != "NAS-01" || one.Note != nil {
		t.Errorf("get after update (trimmed, blank note dropped): %d %+v", c, one)
	}
	var list struct{ Items []db.Nickname }
	e.get(t, "/api/v1/nicknames", &list)
	if len(list.Items) != 2 {
		t.Errorf("list: %+v", list.Items)
	}
	e.get(t, "/api/v1/nicknames?q=google", &list)
	if len(list.Items) != 1 || list.Items[0].IP != "8.8.8.8" {
		t.Errorf("list search: %+v", list.Items)
	}

	// Nicknames surface everywhere IPs are listed.
	var hs struct{ Items []db.HostStat }
	e.get(t, "/api/v1/hosts?since=24h&q=nas-01", &hs)
	if len(hs.Items) != 1 || hs.Items[0].IP != "192.168.1.10" || hs.Items[0].Nickname == nil || *hs.Items[0].Nickname != "NAS-01" {
		t.Errorf("hosts search by nickname: %+v", hs.Items)
	}
	var d struct {
		Host  db.HostStat   `json:"host"`
		Peers []db.HostStat `json:"peers"`
	}
	e.get(t, "/api/v1/hosts/192.168.1.10?since=24h", &d)
	if d.Host.Nickname == nil || *d.Host.Nickname != "NAS-01" {
		t.Errorf("host detail nickname: %+v", d.Host)
	}
	found := false
	for _, p := range d.Peers {
		if p.IP == "8.8.8.8" && p.Nickname != nil && *p.Nickname == "Google DNS" {
			found = true
		}
	}
	if !found {
		t.Errorf("peer nickname missing: %+v", d.Peers)
	}
	var fl struct{ Items []db.Flow }
	e.get(t, "/api/v1/flows?since=24h&ip=8.8.8.8&port=53", &fl)
	if len(fl.Items) == 0 {
		t.Fatal("no flows")
	}
	for _, f := range fl.Items {
		if f.IPSrc == "8.8.8.8" && (f.SrcNickname == nil || *f.SrcNickname != "Google DNS") {
			t.Errorf("flow src nickname: %+v", f)
		}
		if f.IPDst == "192.168.1.10" && (f.DstNickname == nil || *f.DstNickname != "NAS-01") {
			t.Errorf("flow dst nickname: %+v", f)
		}
	}
	e.worker.RunVTOnce(context.Background())
	put("203.0.113.5", `{"nickname":"Bad guy"}`)
	var th struct{ Items []db.Threat }
	e.get(t, "/api/v1/threats?since=24h", &th)
	if len(th.Items) != 1 || th.Items[0].Nickname == nil || *th.Items[0].Nickname != "Bad guy" {
		t.Errorf("threat nickname: %+v", th.Items)
	}

	req, _ := http.NewRequest(http.MethodDelete, e.srv.URL+"/api/v1/nicknames/8.8.8.8", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Errorf("delete: %d", resp.StatusCode)
	}
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("second delete should be 404, got %d", resp.StatusCode)
	}
	if c := e.get(t, "/api/v1/nicknames/8.8.8.8", nil); c != 404 {
		t.Errorf("deleted nickname should be 404, got %d", c)
	}
}

func TestStaticFallback(t *testing.T) {
	e := setup(t)
	if c := e.get(t, "/some/spa/route", nil); c != 404 {
		t.Errorf("without a built frontend expect 404, got %d", c)
	}
	if c := e.get(t, "/api/v1/nope", nil); c != 404 {
		t.Errorf("unknown api route: %d", c)
	}
	_ = fmt.Sprint()
}

func TestDetectionAndAlerts(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	locals := e.cfg.LocalNetworksCIDR()
	now := time.Now().UTC()

	// Recent traffic (fixture rows for 203.0.113.5 are 2h old, outside the rule's 10m window).
	if _, err := e.db.Pool.Exec(ctx, `INSERT INTO acct (ip_src, ip_dst, port_src, port_dst, ip_proto, packets, bytes, stamp_inserted, stamp_updated) VALUES
	 ('192.168.1.20','203.0.113.5',50010,443,6,5,600, date_trunc('minute', now() - interval '2 minutes'), now()),
	 ('203.0.113.5','192.168.1.20',443,50010,6,7,9000, date_trunc('minute', now() - interval '2 minutes'), now())`); err != nil {
		t.Fatal(err)
	}
	// A threat feed list containing an external peer already in the fixture (203.0.113.5).
	if err := e.db.ReplaceThreatList(ctx, "feodo", []string{"203.0.113.0/24", "45.9.148.0/24"}); err != nil {
		t.Fatal(err)
	}
	stats, err := e.db.ThreatListStats(ctx)
	if err != nil || len(stats) != 1 || stats[0].Entries != 2 {
		t.Fatalf("threat list stats: %v %+v", err, stats)
	}
	if lists, _ := e.db.ThreatListsFor(ctx, "203.0.113.5"); len(lists) != 1 || lists[0] != "feodo" {
		t.Errorf("lists for ip: %v", lists)
	}

	// threat_feed rule fires: 192.168.1.20 <-> 203.0.113.5 in the fixture.
	raised, err := e.engine.RunRule(ctx, "threat_feed", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(raised) != 1 || raised[0].Severity != "critical" {
		t.Fatalf("threat_feed raised: %+v", raised)
	}
	// Re-run bumps count, does not create a second alert.
	if _, err := e.engine.RunRule(ctx, "threat_feed", true); err != nil {
		t.Fatal(err)
	}
	var al struct {
		Items []db.Alert `json:"items"`
		Total int64      `json:"total"`
	}
	e.get(t, "/api/v1/alerts", &al)
	if al.Total != 1 || al.Items[0].Count != 2 || al.Items[0].Rule != "threat_feed" {
		t.Fatalf("alerts after two runs: %+v", al)
	}
	id := al.Items[0].ID
	if al.Items[0].Host == nil || *al.Items[0].Host != "192.168.1.20" {
		t.Errorf("alert host: %+v", al.Items[0])
	}

	// Ack, then resolve.
	var a db.Alert
	if c := e.post(t, fmt.Sprintf("/api/v1/alerts/%d/ack", id), &a); c != 200 || a.State != "acked" {
		t.Errorf("ack: %d %+v", c, a)
	}
	e.get(t, "/api/v1/alerts?state=open", &al)
	if al.Total != 0 {
		t.Errorf("acked alert still open: %+v", al)
	}
	if c := e.post(t, fmt.Sprintf("/api/v1/alerts/%d/resolve", id), &a); c != 200 || a.State != "resolved" {
		t.Errorf("resolve: %d %+v", c, a)
	}
	// After resolve, a fresh run creates a NEW alert (dedupe only applies to active alerts).
	if _, err := e.engine.RunRule(ctx, "threat_feed", true); err != nil {
		t.Fatal(err)
	}
	e.get(t, "/api/v1/alerts?state=active", &al)
	if al.Total != 1 || al.Items[0].ID == id {
		t.Errorf("post-resolve re-raise: %+v", al)
	}

	// Reputation rule: enrich peers first (VT flags 203.0.113.5 with 7 malicious).
	e.worker.RunGeoOnce(ctx)
	e.worker.RunVTOnce(ctx)
	rep, err := e.engine.RunRule(ctx, "reputation", true)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rep {
		if r.Peer != nil && *r.Peer == "203.0.113.5" && r.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Errorf("reputation rule should flag 203.0.113.5 critical: %+v", rep)
	}

	// Summary + nav badge.
	var sum db.AlertSummary
	e.get(t, "/api/v1/alerts/summary", &sum)
	if sum.Open == 0 || sum.ByRule["threat_feed"] == 0 {
		t.Errorf("summary: %+v", sum)
	}

	// Host risk shows up on the host row and detail.
	var hs struct {
		Items []db.HostStat `json:"items"`
	}
	e.get(t, "/api/v1/hosts?since=24h&q=192.168.1.20", &hs)
	if len(hs.Items) != 1 || hs.Items[0].Risk == nil || hs.Items[0].Risk.Critical == 0 {
		t.Errorf("host risk: %+v", hs.Items)
	}

	// Rules listing + config update + validation.
	var rl struct {
		Enabled bool             `json:"enabled"`
		Items   []rules.RuleInfo `json:"items"`
	}
	e.get(t, "/api/v1/rules", &rl)
	if !rl.Enabled || len(rl.Items) < 15 {
		t.Fatalf("rules list: %+v", rl.Enabled)
	}
	body := `{"enabled":false,"params":{"min_malicious":4}}`
	req, _ := http.NewRequest(http.MethodPut, e.srv.URL+"/api/v1/rules/reputation", bytes.NewBufferString(body))
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("update rule: %d", resp.StatusCode)
	}
	// disabled rule raises nothing even with data
	if raised, _ := e.engine.RunRule(ctx, "reputation", false); len(raised) != 0 {
		t.Errorf("disabled rule should not raise: %+v", raised)
	}
	// bad param rejected
	req, _ = http.NewRequest(http.MethodPut, e.srv.URL+"/api/v1/rules/reputation", bytes.NewBufferString(`{"params":{"nope":1}}`))
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("bad param should be 400, got %d", resp.StatusCode)
	}
	_ = now
	_ = locals
}

func TestAllRulesRunClean(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	// Build rollups so history-based rules (new_destination, volume_anomaly, new_host) have data.
	if _, err := e.db.RollupHours(ctx, e.cfg.LocalNetworksCIDR(), time.Now().Add(-30*24*time.Hour), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.RollupPeerDays(ctx, e.cfg.LocalNetworksCIDR(), time.Now().Add(-30*24*time.Hour), time.Now()); err != nil {
		t.Fatal(err)
	}
	// Every built-in rule must evaluate without a SQL/runtime error, even on sparse data.
	for _, r := range e.engine.Rules() {
		if _, err := e.engine.RunRule(ctx, r.Name, true); err != nil {
			t.Errorf("rule %s failed: %v", r.Name, err)
		}
	}
	// geo_policy with a country set must also run.
	if err := e.engine.UpdateConfig(ctx, "geo_policy", rules.RuleConfig{Params: map[string]any{"countries": []any{"US", "AU"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.engine.RunRule(ctx, "geo_policy", true); err != nil {
		t.Errorf("geo_policy with countries failed: %v", err)
	}
}

func TestSuricataAndNames(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	// EVE alert wrapped in a syslog frame; 10.0.0.5 is local. Fresh timestamp so the 1h window covers it.
	ts := time.Now().Format("2006-01-02T15:04:05.000000-0700")
	line := `<134>Aug 27 12:00:00 pfsense suricata: {"timestamp":"` + ts + `","event_type":"alert","src_ip":"45.9.148.10","src_port":6667,"dest_ip":"10.0.0.5","dest_port":443,"proto":"TCP","app_proto":"tls","alert":{"action":"allowed","signature_id":2404000,"signature":"ET CNC Feodo","category":"trojan","severity":1}}`
	e.ids.HandleLine(ctx, line)
	if _, err := e.db.SetNickname(ctx, "10.0.0.5", "Kiosk", nil, "iot"); err != nil {
		t.Fatal(err)
	}
	// DNS answer teaches a name; TLS SNI too.
	e.ids.HandleLine(ctx, `{"event_type":"dns","dns":{"type":"answer","rrname":"cdn.example.net","answers":[{"rrname":"cdn.example.net","rrtype":"A","rdata":"203.0.113.5"}]}}`)
	e.ids.HandleLine(ctx, `{"event_type":"tls","dest_ip":"1.1.1.1","tls":{"sni":"one.one.one.one"}}`)

	if s := e.ids.Stats(); s.Alerts != 1 || s.Names < 2 {
		t.Fatalf("ids stats: %+v", s)
	}
	var ev struct {
		Items []db.IDSEvent `json:"items"`
	}
	e.get(t, "/api/v1/ids/events?since=1h", &ev)
	if len(ev.Items) != 1 || ev.Items[0].DstName == nil || *ev.Items[0].DstName != "Kiosk" {
		t.Fatalf("ids events (dst nickname): %+v", ev.Items)
	}
	if *ev.Items[0].SID != 2404000 {
		t.Errorf("sid: %+v", ev.Items[0])
	}
	// The IDS alert became an analyzer alert, host=10.0.0.5 (local), critical.
	var al struct {
		Items []db.Alert `json:"items"`
	}
	e.get(t, "/api/v1/alerts?rule=ids", &al)
	if len(al.Items) != 1 || al.Items[0].Severity != "critical" || al.Items[0].Host == nil || *al.Items[0].Host != "10.0.0.5" {
		t.Fatalf("ids alert: %+v", al.Items)
	}
	// The alert links to the exact stored event, and the event endpoint returns its raw EVE record.
	var details map[string]any
	_ = json.Unmarshal(al.Items[0].Details, &details)
	evID, _ := details["ids_event_id"].(float64)
	if evID <= 0 {
		t.Fatalf("alert details lack ids_event_id: %s", al.Items[0].Details)
	}
	var one db.IDSEvent
	if code := e.get(t, fmt.Sprintf("/api/v1/ids/events/%d", int64(evID)), &one); code != 200 {
		t.Fatalf("ids event by id: http %d", code)
	}
	if one.ID != int64(evID) || one.SID == nil || *one.SID != 2404000 || !bytes.Contains(one.Raw, []byte("ET CNC Feodo")) || one.DstName == nil || *one.DstName != "Kiosk" {
		t.Fatalf("ids event by id: %+v raw=%s", one, one.Raw)
	}
	if code := e.get(t, "/api/v1/ids/events/999999999", nil); code != 404 {
		t.Errorf("missing ids event: http %d, want 404", code)
	}
	// Per-type ingest counters: alert, dns.answer and tls each seen once; the listener knows what they feed.
	st := e.ids.Stats()
	seen := map[string]suricata.TypeStat{}
	for _, ts := range st.Types {
		seen[ts.Type] = ts
	}
	if seen["alert"].Count != 1 || seen["alert"].Used != "alerts" || seen["dns.answer"].Count != 1 || seen["dns.answer"].Used != "names" || seen["tls"].Used != "names" || st.LastEvent == nil {
		t.Errorf("ingest counters: %+v", st.Types)
	}

	// Names surface on the enrichment record and host row.
	var names struct {
		Items []db.IPName `json:"items"`
	}
	e.get(t, "/api/v1/ips/203.0.113.5/names", &names)
	if len(names.Items) != 1 || names.Items[0].Name != "cdn.example.net" || names.Items[0].Source != "dns" {
		t.Errorf("ip names: %+v", names.Items)
	}

	// IDS summary.
	var sum struct {
		Items   []db.IDSSignatureStat `json:"items"`
		Enabled bool                  `json:"enabled"`
	}
	e.get(t, "/api/v1/ids/summary?since=1h", &sum)
	if !sum.Enabled || len(sum.Items) != 1 || sum.Items[0].Count != 1 {
		t.Errorf("ids summary: %+v", sum)
	}
}

func TestRollupsAndReputation(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	// Build rollups from the fixture, then read one host's hourly series.
	if _, err := e.db.RollupHours(ctx, e.cfg.LocalNetworksCIDR(), time.Now().Add(-25*time.Hour), time.Now()); err != nil {
		t.Fatal(err)
	}
	hp, err := e.db.HostHourly(ctx, "192.168.1.10", time.Now().Add(-25*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(hp) == 0 {
		t.Fatalf("expected hourly rollups for 192.168.1.10")
	}
	var totalOut int64
	for _, p := range hp {
		totalOut += p.BytesOut
	}
	if totalOut != 1644 { // matches TestOverviewTotals for this host
		t.Errorf("rollup bytes_out = %d, want 1644", totalOut)
	}

	// Reputation storage + candidate ordering + flagging via the generic lane.
	score := 90
	if err := e.db.UpsertReputation(ctx, "203.0.113.5", "abuseipdb", &db.Reputation{Source: "abuseipdb", Status: "ok", Score: &score, Flagged: true, Data: []byte(`{"score":90}`)}); err != nil {
		t.Fatal(err)
	}
	reps, err := e.db.ReputationFor(ctx, "203.0.113.5")
	if err != nil || len(reps) != 1 || !reps[0].Flagged {
		t.Fatalf("reputation: %v %+v", err, reps)
	}
	day, _, _ := e.db.ReputationUsage(ctx, "abuseipdb")
	if day != 1 {
		t.Errorf("reputation usage day = %d", day)
	}
	rs, _ := e.db.ReputationStats(ctx)
	if len(rs) != 1 || rs[0].Flagged != 1 {
		t.Errorf("reputation stats: %+v", rs)
	}
}

func TestSystemStatus(t *testing.T) {
	e := setup(t)
	var st map[string]any
	if c := e.get(t, "/api/v1/system/status", &st); c != 200 {
		t.Fatalf("system status: %d", c)
	}
	if st["rules_enabled"] != true || st["suricata_enabled"] != true {
		t.Errorf("status flags: %+v", st)
	}
}
