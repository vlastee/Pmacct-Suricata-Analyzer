// Command server runs the pmacct-analyzer API and serves the frontend.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/api"
	"github.com/deezave/pmacct-analyzer/backend/internal/auth"
	"github.com/deezave/pmacct-analyzer/backend/internal/config"
	"github.com/deezave/pmacct-analyzer/backend/internal/db"
	"github.com/deezave/pmacct-analyzer/backend/internal/enrich"
	"github.com/deezave/pmacct-analyzer/backend/internal/feeds"
	"github.com/deezave/pmacct-analyzer/backend/internal/notify"
	"github.com/deezave/pmacct-analyzer/backend/internal/rules"
	"github.com/deezave/pmacct-analyzer/backend/internal/scheduler"
	"github.com/deezave/pmacct-analyzer/backend/internal/suricata"
	"github.com/deezave/pmacct-analyzer/backend/internal/tlsca"
)

func main() {
	level := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	database, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database", "err", err)
		os.Exit(1)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		slog.Error("migrate", "err", err)
		os.Exit(1)
	}

	srv := &api.Server{DB: database, Cfg: cfg}
	httpc := &http.Client{Timeout: cfg.HTTPTimeout}

	// Authentication.
	if cfg.AuthEnabled {
		authSvc := &auth.Service{DB: database, Cfg: cfg}
		if err := authSvc.EnsureAdmin(ctx); err != nil {
			slog.Error("seed admin", "err", err)
			os.Exit(1)
		}
		srv.Auth = authSvc
		slog.Info("authentication enabled", "session_ttl", cfg.SessionTTL, "login_max_failures", cfg.LoginMaxFailures, "login_lockout", cfg.LoginLockout)
	} else {
		slog.Warn("AUTHENTICATION DISABLED (AUTH_ENABLED=false) — the UI and API are open to anyone who can reach them")
	}

	// Notifications.
	notifier := notify.NewDispatcher(database, cfg, httpc)
	if len(notifier.Channels) > 0 {
		srv.Notifier = notifier
		go notifier.Run(ctx)
		slog.Info("notifications enabled", "channels", notifier.ChannelNames(), "min_severity", cfg.NotifyMinSeverity, "digest", cfg.NotifyDigest)
	}

	if cfg.EnrichEnabled {
		var provider enrich.Provider = &enrich.IPAPI{BaseURL: cfg.IPAPIBaseURL, Client: httpc}
		if cfg.IPInfoToken != "" {
			provider = &enrich.IPInfoIO{BaseURL: cfg.IPInfoBaseURL, Token: cfg.IPInfoToken, Client: httpc}
		}
		if cfg.GeoIPCityDB != "" && cfg.GeoIPASNDB != "" {
			mm, err := enrich.OpenMaxMind(cfg.GeoIPCityDB, cfg.GeoIPASNDB)
			if err != nil {
				slog.Error("maxmind", "err", err)
				os.Exit(1)
			}
			defer mm.Close()
			provider = mm
		}
		var vt *enrich.VirusTotal
		if cfg.VTAPIKey != "" {
			vt = &enrich.VirusTotal{BaseURL: cfg.VTBaseURL, APIKey: cfg.VTAPIKey, Client: httpc}
		}
		worker := scheduler.New(database, cfg, &enrich.Enricher{Provider: provider, ReverseDNS: cfg.ReverseDNS}, vt)
		if cfg.AbuseIPDBKey != "" {
			worker.AddRepLane(&scheduler.RepLane{Provider: &enrich.AbuseIPDB{BaseURL: cfg.AbuseIPDBBaseURL, APIKey: cfg.AbuseIPDBKey, Client: httpc},
				RateLimit: cfg.AbuseIPDBRateLimit, DailyQuota: cfg.AbuseIPDBDailyQuota, RefreshAfter: cfg.AbuseIPDBRefresh})
		}
		if cfg.GreyNoiseKey != "" {
			worker.AddRepLane(&scheduler.RepLane{Provider: &enrich.GreyNoise{BaseURL: cfg.GreyNoiseBaseURL, APIKey: cfg.GreyNoiseKey, Client: httpc},
				RateLimit: cfg.GreyNoiseRateLimit, DailyQuota: cfg.GreyNoiseDailyQuota, RefreshAfter: cfg.GreyNoiseRefresh})
		}
		if cfg.OTXKey != "" {
			worker.AddRepLane(&scheduler.RepLane{Provider: &enrich.OTX{BaseURL: cfg.OTXBaseURL, APIKey: cfg.OTXKey, Client: httpc},
				RateLimit: cfg.OTXRateLimit, DailyQuota: cfg.OTXDailyQuota, RefreshAfter: cfg.OTXRefresh})
		}
		if cfg.FileIntelEnabled {
			fl := &scheduler.FilesLane{VT: vt, RefreshAfter: cfg.FileVTRefreshAfter, BatchSize: cfg.VTBatchSize}
			if cfg.MHREnabled {
				fl.MHR = &enrich.MHR{}
			}
			if fl.VT != nil || fl.MHR != nil {
				worker.EnableFiles(fl)
			}
		}
		srv.Worker = worker
		go worker.Run(ctx)
		slog.Info("enrichment worker started", "geo_provider", provider.Name(), "virustotal", vt != nil, "reputation_lanes", len(worker.Rep),
			"interval", cfg.EnrichInterval, "vt_daily_quota", cfg.VTDailyQuota)
	}

	// Threat feeds and the LOLBAS / GTFOBins catalogues.
	if len(cfg.ThreatFeeds) > 0 || cfg.LOLBASURL != "" || cfg.GTFOBinsURL != "" {
		fc := &http.Client{Timeout: 90 * time.Second}
		f := &feeds.Fetcher{DB: database, Feeds: cfg.ThreatFeeds, Client: fc, Interval: cfg.ThreatFeedsInterval}
		if cfg.LOLBASURL != "" || cfg.GTFOBinsURL != "" {
			f.LOLBins = &feeds.LOLBins{DB: database, Client: fc, LOLBASURL: cfg.LOLBASURL, GTFOBinsURL: cfg.GTFOBinsURL}
		}
		srv.Feeds = f
		go f.Run(ctx)
		slog.Info("threat feeds enabled", "feeds", len(cfg.ThreatFeeds), "interval", cfg.ThreatFeedsInterval, "lolbins", f.LOLBins != nil)
	}

	// Rules engine.
	var engine *rules.Engine
	if cfg.RulesEnabled {
		var n rules.Notifier
		if srv.Notifier != nil {
			n = srv.Notifier
		}
		e, err := rules.New(ctx, database, cfg, n)
		if err != nil {
			slog.Error("rules", "err", err)
			os.Exit(1)
		}
		engine = e
		srv.Rules = e
		go e.Run(ctx)
		slog.Info("rules engine started", "rules", len(e.Rules()), "interval", cfg.RulesInterval)
	}

	// Suricata ingest.
	if cfg.SuricataListen != "" {
		l := &suricata.Listener{DB: database, Addr: cfg.SuricataListen, IsLocal: cfg.IsLocal}
		if engine != nil {
			l.Sink = engine
		}
		srv.Suricata = l
		go func() {
			if err := l.Run(ctx); err != nil {
				slog.Error("suricata listener", "err", err)
			}
		}()
	}

	hs := &http.Server{Addr: cfg.ListenAddr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()

	// Built-in HTTPS listener (internal CA, or a certificate file pair).
	if cfg.TLSListenAddr != "" {
		tcfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			pair, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
			if err != nil {
				slog.Error("tls certificate files", "err", err)
				os.Exit(1)
			}
			tcfg.Certificates = []tls.Certificate{pair}
			slog.Info("https listening with certificate files", "addr", cfg.TLSListenAddr)
		} else {
			mgr, err := tlsca.New(ctx, database, cfg.TLSHosts)
			if err != nil {
				slog.Error("tls", "err", err)
				os.Exit(1)
			}
			srv.TLS = mgr
			tcfg = mgr.TLSConfig()
			go mgr.Run(ctx)
			info := mgr.Info()
			slog.Info("https listening with internal CA", "addr", cfg.TLSListenAddr, "hosts", info.Hosts, "ca_fingerprint", info.CAFingerprint)
		}
		hts := &http.Server{Addr: cfg.TLSListenAddr, Handler: srv.Handler(), TLSConfig: tcfg, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = hts.Shutdown(sctx)
		}()
		go func() {
			if err := hts.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("https server", "err", err)
				os.Exit(1)
			}
		}()
	}
	slog.Info("listening", "addr", cfg.ListenAddr, "local_networks", cfg.LocalNetworksCIDR())
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server", "err", err)
		os.Exit(1)
	}
}
