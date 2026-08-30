// Package scheduler runs the periodic enrichment workers ("lanes"):
//   - geo: ASN / geolocation / rDNS via ip-api.com or ipinfo.io
//   - vt:  reputation via VirusTotal, under a strict daily quota
package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/config"
	"github.com/deezave/pmacct-analyzer/backend/internal/db"
	"github.com/deezave/pmacct-analyzer/backend/internal/enrich"
)

// LaneStats is a snapshot of one lane's activity.
type LaneStats struct {
	Enabled        bool      `json:"enabled"`
	Provider       string    `json:"provider"`
	Running        bool      `json:"running"`
	LastRun        time.Time `json:"last_run"`
	LastBatchSize  int       `json:"last_batch_size"`
	Runs           int64     `json:"runs"`
	Lookups        int64     `json:"lookups"`
	Failures       int64     `json:"failures"`
	Interval       string    `json:"interval"`
	RefreshAfter   string    `json:"refresh_after"`
	RateLimit      string    `json:"rate_limit"`
	DailyQuota     int       `json:"daily_quota,omitempty"`
	QuotaUsed      int64     `json:"quota_used,omitempty"`
	MonthlyQuota   int       `json:"monthly_quota,omitempty"`
	QuotaUsedMonth int64     `json:"quota_used_month,omitempty"`
	QuotaHit       bool      `json:"quota_hit,omitempty"`
}

type lane struct {
	mu       sync.Mutex
	lastRun  time.Time
	lastN    int
	running  atomic.Bool
	runs     atomic.Int64
	lookups  atomic.Int64
	failures atomic.Int64
	quotaHit atomic.Bool
	kick     chan struct{}
}

func newLane() *lane { return &lane{kick: make(chan struct{}, 1)} }

func (l *lane) finish(n int) {
	l.mu.Lock()
	l.lastRun, l.lastN = time.Now(), n
	l.mu.Unlock()
	l.runs.Add(1)
}

// RepLane is a quota-limited reputation source (AbuseIPDB, GreyNoise).
type RepLane struct {
	Provider     enrich.ReputationProvider
	RateLimit    time.Duration
	DailyQuota   int
	RefreshAfter time.Duration
	BatchSize    int
	l            *lane
}

// Worker owns the enrichment lanes and the maintenance jobs (rollups, pruning).
type Worker struct {
	DB  *db.DB
	Cfg *config.Config
	Geo *enrich.Enricher   // nil disables the geo lane
	VT  *enrich.VirusTotal // nil disables the VT lane
	Rep []*RepLane

	geo     *lane
	vt      *lane
	rollups *lane
}

// New constructs a Worker.
func New(d *db.DB, cfg *config.Config, geo *enrich.Enricher, vt *enrich.VirusTotal) *Worker {
	return &Worker{DB: d, Cfg: cfg, Geo: geo, VT: vt, geo: newLane(), vt: newLane(), rollups: newLane()}
}

// AddRepLane registers a reputation lane.
func (w *Worker) AddRepLane(r *RepLane) {
	r.l = newLane()
	if r.BatchSize <= 0 {
		r.BatchSize = 100
	}
	w.Rep = append(w.Rep, r)
}

// Stats returns a snapshot of both lanes.
func (w *Worker) Stats(ctx context.Context) map[string]LaneStats {
	out := map[string]LaneStats{}
	snap := func(l *lane, s LaneStats) LaneStats {
		l.mu.Lock()
		s.LastRun, s.LastBatchSize = l.lastRun, l.lastN
		l.mu.Unlock()
		s.Running, s.Runs, s.Lookups, s.Failures = l.running.Load(), l.runs.Load(), l.lookups.Load(), l.failures.Load()
		return s
	}
	g := LaneStats{Enabled: w.Geo != nil, Interval: w.Cfg.EnrichInterval.String(), RefreshAfter: w.Cfg.EnrichRefreshAfter.String(), RateLimit: w.Cfg.EnrichRateLimit.String()}
	if w.Geo != nil {
		g.Provider = w.Geo.Provider.Name()
	}
	out["geo"] = snap(w.geo, g)
	v := LaneStats{Enabled: w.VT != nil, Provider: "virustotal", Interval: w.Cfg.EnrichInterval.String(), RefreshAfter: w.Cfg.VTRefreshAfter.String(),
		RateLimit: w.Cfg.VTRateLimit.String(), DailyQuota: w.Cfg.VTDailyQuota, MonthlyQuota: w.Cfg.VTMonthlyQuota, QuotaHit: w.vt.quotaHit.Load()}
	if w.VT != nil {
		if day, month, err := w.DB.VTUsage(ctx); err == nil {
			v.QuotaUsed, v.QuotaUsedMonth = day, month
		}
	}
	out["vt"] = snap(w.vt, v)
	for _, r := range w.Rep {
		rs := LaneStats{Enabled: true, Provider: r.Provider.Name(), Interval: w.Cfg.EnrichInterval.String(), RefreshAfter: r.RefreshAfter.String(),
			RateLimit: r.RateLimit.String(), DailyQuota: r.DailyQuota, QuotaHit: r.l.quotaHit.Load()}
		if day, month, err := w.DB.ReputationUsage(ctx, r.Provider.Name()); err == nil {
			rs.QuotaUsed, rs.QuotaUsedMonth = day, month
		}
		out[r.Provider.Name()] = snap(r.l, rs)
	}
	out["rollups"] = snap(w.rollups, LaneStats{Enabled: true, Provider: "rollups", Interval: "5m0s"})
	return out
}

// Kick requests an immediate run of all lanes (non-blocking).
func (w *Worker) Kick() {
	lanes := []*lane{w.geo, w.vt}
	for _, r := range w.Rep {
		lanes = append(lanes, r.l)
	}
	for _, l := range lanes {
		select {
		case l.kick <- struct{}{}:
		default:
		}
	}
}

// Run starts both lane loops and blocks until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	var wg sync.WaitGroup
	loop := func(l *lane, run func(context.Context) int) {
		defer wg.Done()
		t := time.NewTicker(w.Cfg.EnrichInterval)
		defer t.Stop()
		run(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				run(ctx)
			case <-l.kick:
				run(ctx)
			}
		}
	}
	if w.Geo != nil {
		wg.Add(1)
		go loop(w.geo, w.RunGeoOnce)
	}
	if w.VT != nil {
		wg.Add(1)
		go loop(w.vt, w.RunVTOnce)
	}
	for _, r := range w.Rep {
		r := r
		wg.Add(1)
		go loop(r.l, func(ctx context.Context) int { return w.RunRepOnce(ctx, r) })
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		w.RunRollupsOnce(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				w.RunRollupsOnce(ctx)
			}
		}
	}()
	wg.Wait()
}

// RunOnce runs all lanes sequentially (used by tests and the manual trigger endpoint).
func (w *Worker) RunOnce(ctx context.Context) int {
	n := w.RunGeoOnce(ctx) + w.RunVTOnce(ctx)
	for _, r := range w.Rep {
		n += w.RunRepOnce(ctx, r)
	}
	return n
}

// RunRepOnce performs one pass of a reputation lane within its daily quota.
func (w *Worker) RunRepOnce(ctx context.Context, r *RepLane) int {
	if !r.l.running.CompareAndSwap(false, true) {
		return 0
	}
	defer r.l.running.Store(false)
	name := r.Provider.Name()
	used, _, err := w.DB.ReputationUsage(ctx, name)
	if err != nil {
		slog.Error("reputation lane: usage", "source", name, "err", err)
		return 0
	}
	budget := int64(r.DailyQuota) - used
	if budget <= 0 {
		r.l.quotaHit.Store(true)
		r.l.finish(0)
		return 0
	}
	limit := r.BatchSize
	if int64(limit) > budget {
		limit = int(budget)
	}
	since := time.Now().Add(-w.Cfg.EnrichLookbackWindow)
	ips, err := w.DB.ReputationCandidates(ctx, name, since, w.Cfg.LocalNetworksCIDR(), r.RefreshAfter, limit)
	if err != nil {
		slog.Error("reputation lane: candidates", "source", name, "err", err)
		return 0
	}
	r.l.quotaHit.Store(false)
	attempted, ok := 0, 0
	for i, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		attempted++
		lctx, cancel := context.WithTimeout(ctx, w.Cfg.HTTPTimeout+5*time.Second)
		res, err := r.Provider.Lookup(lctx, ip)
		cancel()
		r.l.lookups.Add(1)
		if errors.Is(err, enrich.ErrQuotaExceeded) {
			r.l.quotaHit.Store(true)
			slog.Warn("reputation lane: quota exceeded; stopping pass", "source", name)
			break
		}
		if err != nil {
			r.l.failures.Add(1)
			msg := err.Error()
			res = &db.Reputation{Source: name, Status: "failed", Error: &msg}
		} else {
			ok++
		}
		if err := w.DB.UpsertReputation(ctx, ip, name, res); err != nil {
			slog.Error("reputation lane: store", "source", name, "ip", ip, "err", err)
		}
		if i < len(ips)-1 {
			w.pause(ctx, r.RateLimit)
		}
	}
	r.l.finish(attempted)
	if attempted > 0 {
		slog.Info("reputation pass", "source", name, "attempted", attempted, "ok", ok)
	}
	return attempted
}

// RunRollupsOnce maintains host_hourly / host_peer_daily and prunes old data.
func (w *Worker) RunRollupsOnce(ctx context.Context) int {
	if !w.rollups.running.CompareAndSwap(false, true) {
		return 0
	}
	defer w.rollups.running.Store(false)
	now := time.Now().UTC()
	locals := w.Cfg.LocalNetworksCIDR()
	var backfilled bool
	if ok, _ := w.DB.GetSetting(ctx, "rollup_hours_backfilled", &backfilled); !ok || !backfilled {
		// First run: build hourly rollups from all raw data still present (chunked per day).
		start := now.Add(-8 * 24 * time.Hour).Truncate(24 * time.Hour)
		for t := start; t.Before(now); t = t.Add(24 * time.Hour) {
			if _, err := w.DB.RollupHours(ctx, locals, t, t.Add(24*time.Hour)); err != nil {
				slog.Error("rollup backfill", "err", err)
				return 0
			}
		}
		_ = w.DB.SetSetting(ctx, "rollup_hours_backfilled", true)
		slog.Info("hourly rollups backfilled")
	}
	if _, err := w.DB.RollupHours(ctx, locals, now.Add(-2*time.Hour), now); err != nil {
		slog.Error("rollup hours", "err", err)
		return 0
	}
	// Peer/day rollups are incremental behind a cursor, lagging 3 minutes for late pmacct updates.
	var cursor time.Time
	if ok, _ := w.DB.GetSetting(ctx, "rollup_peer_cursor", &cursor); !ok || cursor.IsZero() {
		cursor = now.Add(-8 * 24 * time.Hour)
	}
	end := now.Add(-3 * time.Minute)
	for cursor.Before(end) {
		next := cursor.Add(6 * time.Hour)
		if next.After(end) {
			next = end
		}
		if _, err := w.DB.RollupPeerDays(ctx, locals, cursor, next); err != nil {
			slog.Error("rollup peers", "err", err)
			return 0
		}
		cursor = next
		_ = w.DB.SetSetting(ctx, "rollup_peer_cursor", cursor)
	}
	var lastPrune time.Time
	if ok, _ := w.DB.GetSetting(ctx, "last_prune", &lastPrune); !ok || now.Sub(lastPrune) > 24*time.Hour {
		if err := w.DB.PruneRollups(ctx, 180*24*time.Hour, 60*24*time.Hour, 30*24*time.Hour); err != nil {
			slog.Error("prune", "err", err)
		} else {
			_ = w.DB.SetSetting(ctx, "last_prune", now)
		}
		if ret, err := w.DB.GetAgentRetention(ctx); err == nil {
			if conns, agents, err := w.DB.PruneAgentData(ctx, ret); err != nil {
				slog.Error("prune agent data", "err", err)
			} else if conns > 0 || agents > 0 {
				slog.Info("pruned agent data", "conn_rows", conns, "stale_agents", agents)
			}
		}
		if ret, err := w.DB.GetAlertRetention(ctx); err == nil {
			if n, err := w.DB.PruneResolvedAlerts(ctx, ret); err != nil {
				slog.Error("prune alerts", "err", err)
			} else if len(n) > 0 {
				slog.Info("deleted old resolved alerts", "by_severity", n)
			}
		}
	}
	_ = w.DB.PurgeExpiredSessions(ctx)
	_ = w.DB.PurgeExpiredIPRules(ctx)
	w.rollups.finish(1)
	return 1
}

func (w *Worker) pause(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// RunGeoOnce performs one geo discovery + enrichment pass. Returns the number of candidates.
func (w *Worker) RunGeoOnce(ctx context.Context) int {
	if w.Geo == nil || !w.geo.running.CompareAndSwap(false, true) {
		return 0
	}
	defer w.geo.running.Store(false)
	since := time.Now().Add(-w.Cfg.EnrichLookbackWindow)
	ips, err := w.DB.EnrichmentCandidates(ctx, since, w.Cfg.LocalNetworksCIDR(), w.Cfg.EnrichRefreshAfter, w.Cfg.EnrichBatchSize)
	if err != nil {
		slog.Error("geo enrichment: candidates", "err", err)
		return 0
	}
	ok := 0
	for i, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		if w.LookupAndStore(ctx, ip) {
			ok++
		}
		if i < len(ips)-1 {
			w.pause(ctx, w.Cfg.EnrichRateLimit)
		}
	}
	w.geo.finish(len(ips))
	if len(ips) > 0 {
		slog.Info("geo enrichment pass", "candidates", len(ips), "ok", ok)
	}
	return len(ips)
}

// LookupAndStore enriches a single IP through the geo lane and persists the result.
func (w *Worker) LookupAndStore(ctx context.Context, ip string) bool {
	if w.Geo == nil {
		return false
	}
	lctx, cancel := context.WithTimeout(ctx, w.Cfg.HTTPTimeout+5*time.Second)
	defer cancel()
	info := w.Geo.Lookup(lctx, ip)
	w.geo.lookups.Add(1)
	if info.Status != "ok" {
		w.geo.failures.Add(1)
		slog.Warn("geo lookup failed", "ip", ip, "err", *info.Error)
	}
	if err := w.DB.UpsertIPInfo(ctx, info); err != nil {
		slog.Error("geo enrichment: store", "ip", ip, "err", err)
		return false
	}
	return info.Status == "ok"
}

// RunVTOnce performs one VirusTotal pass within the remaining daily quota. Returns the
// number of lookups attempted.
func (w *Worker) RunVTOnce(ctx context.Context) int {
	if w.VT == nil || !w.vt.running.CompareAndSwap(false, true) {
		return 0
	}
	defer w.vt.running.Store(false)
	used, usedMonth, err := w.DB.VTUsage(ctx)
	if err != nil {
		slog.Error("vt enrichment: quota", "err", err)
		return 0
	}
	budget := int64(w.Cfg.VTDailyQuota) - used
	if w.Cfg.VTMonthlyQuota > 0 && int64(w.Cfg.VTMonthlyQuota)-usedMonth < budget {
		budget = int64(w.Cfg.VTMonthlyQuota) - usedMonth
	}
	if budget <= 0 {
		w.vt.quotaHit.Store(true)
		w.vt.finish(0)
		slog.Info("vt enrichment: quota exhausted", "used_today", used, "daily_quota", w.Cfg.VTDailyQuota,
			"used_month", usedMonth, "monthly_quota", w.Cfg.VTMonthlyQuota)
		return 0
	}
	limit := w.Cfg.VTBatchSize
	if int64(limit) > budget {
		limit = int(budget)
	}
	since := time.Now().Add(-w.Cfg.EnrichLookbackWindow)
	ips, err := w.DB.VTCandidates(ctx, since, w.Cfg.LocalNetworksCIDR(), w.Cfg.VTRefreshAfter, limit)
	if err != nil {
		slog.Error("vt enrichment: candidates", "err", err)
		return 0
	}
	w.vt.quotaHit.Store(false)
	attempted, ok := 0, 0
	for i, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		attempted++
		res, quota := w.LookupVT(ctx, ip)
		if quota {
			w.vt.quotaHit.Store(true)
			slog.Warn("vt enrichment: provider reported quota exceeded; stopping pass", "attempted", attempted)
			break
		}
		if res {
			ok++
		}
		if i < len(ips)-1 {
			w.pause(ctx, w.Cfg.VTRateLimit)
		}
	}
	w.vt.finish(attempted)
	if attempted > 0 {
		slog.Info("vt enrichment pass", "candidates", len(ips), "attempted", attempted, "ok", ok, "used_today", used+int64(attempted))
	}
	return attempted
}

// LookupVT queries VirusTotal for one IP and stores the result. Returns (ok, quotaExceeded).
// A quota error is not stored, so the IP stays first in line for the next pass.
func (w *Worker) LookupVT(ctx context.Context, ip string) (bool, bool) {
	if w.VT == nil {
		return false, false
	}
	lctx, cancel := context.WithTimeout(ctx, w.Cfg.HTTPTimeout+5*time.Second)
	defer cancel()
	res, err := w.VT.Lookup(lctx, ip)
	w.vt.lookups.Add(1)
	if errors.Is(err, enrich.ErrQuotaExceeded) {
		return false, true
	}
	if err != nil {
		w.vt.failures.Add(1)
		msg := err.Error()
		res = &db.VTResult{Status: "failed", Error: &msg}
		slog.Warn("vt lookup failed", "ip", ip, "err", msg)
	}
	if err := w.DB.UpsertVT(ctx, ip, res); err != nil {
		slog.Error("vt enrichment: store", "ip", ip, "err", err)
		return false, false
	}
	return res.Status == "ok", false
}
