// Package config loads runtime configuration from environment variables.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime settings for the analyzer.
type Config struct {
	ListenAddr string
	// Built-in HTTPS: when TLSListenAddr is set the server also serves TLS there with an internal
	// CA (generated on first start, stored in the database) for TLSHosts, or with TLSCertFile/
	// TLSKeyFile when both are given.
	TLSListenAddr string
	TLSHosts      []string
	TLSCertFile   string
	TLSKeyFile    string
	// Directory holding the endpoint agent binaries served to installers (AGENT_DIST_DIR).
	AgentDistDir string
	DatabaseURL  string
	StaticDir    string

	// LocalNetworks are the CIDR prefixes considered "local"/internal.
	LocalNetworks []netip.Prefix

	// Enrichment settings.
	EnrichEnabled        bool
	EnrichInterval       time.Duration // how often to scan for new/stale IPs
	EnrichRefreshAfter   time.Duration // re-fetch data older than this
	EnrichBatchSize      int           // max IPs per scan
	EnrichRateLimit      time.Duration // min delay between external lookups
	EnrichLookbackWindow time.Duration // only consider IPs seen within this window
	IPAPIBaseURL         string        // ip-api.com compatible endpoint
	IPInfoToken          string        // optional ipinfo.io token (used when set)
	IPInfoBaseURL        string
	ReverseDNS           bool
	HTTPTimeout          time.Duration

	// VirusTotal lane (enabled when VTAPIKey is set).
	VTAPIKey       string
	VTBaseURL      string
	VTRateLimit    time.Duration // free tier: 4 req/min -> 15s
	VTDailyQuota   int           // free tier: 500/day
	VTMonthlyQuota int           // free tier: 15500/month
	VTRefreshAfter time.Duration // re-check known IPs still seen in traffic after this
	VTBatchSize    int

	// AbuseIPDB lane (enabled when key set). Free: 1000/day.
	AbuseIPDBKey        string
	AbuseIPDBBaseURL    string
	AbuseIPDBRateLimit  time.Duration
	AbuseIPDBDailyQuota int
	AbuseIPDBRefresh    time.Duration
	// GreyNoise community lane (enabled when key set).
	GreyNoiseKey        string
	GreyNoiseBaseURL    string
	GreyNoiseRateLimit  time.Duration
	GreyNoiseDailyQuota int
	GreyNoiseRefresh    time.Duration
	// AlienVault OTX lane (enabled when key set).
	OTXKey        string
	OTXBaseURL    string
	OTXRateLimit  time.Duration
	OTXDailyQuota int
	OTXRefresh    time.Duration
	// MaxMind GeoLite2 local databases (used as geo provider when both paths are set).
	GeoIPCityDB string
	GeoIPASNDB  string

	// Threat feeds: "name=url,name=url". Empty string disables.
	ThreatFeeds         map[string]string
	ThreatFeedsInterval time.Duration
	// Catalogues of abusable system binaries (empty URL disables), refreshed daily.
	LOLBASURL   string
	GTFOBinsURL string
	// File intelligence for executables reported by agents: VirusTotal file reports (needs
	// VTAPIKey; shares its quota) and the Team Cymru Malware Hash Registry (DNS, keyless).
	FileIntelEnabled   bool
	FileVTRefreshAfter time.Duration
	MHREnabled         bool

	// Rules engine.
	RulesEnabled  bool
	RulesInterval time.Duration
	Gateways      []netip.Addr // hosts allowed to talk DNS/NTP outside etc. (the router)

	// Suricata EVE ingest (syslog over UDP/TCP). Empty disables.
	SuricataListen string

	// Notifications.
	NotifyWebhookURL    string
	NotifyNtfyURL       string
	NotifyNtfyToken     string
	NotifyGotifyURL     string
	NotifyGotifyToken   string
	NotifyTelegramToken string
	NotifyTelegramChat  string
	NotifySlackWebhook  string
	NotifySMTPHost      string
	NotifySMTPPort      int
	NotifySMTPUser      string
	NotifySMTPPass      string
	NotifySMTPFrom      string
	NotifySMTPTo        string
	NotifyMinSeverity   string
	NotifyDigest        time.Duration // 0 = immediate
	NotifyQuietHours    string        // "23-7" local time, empty = none
	NotifyRenotifyAfter time.Duration
	PublicURL           string // used in notification links

	// Authentication.
	AuthEnabled       bool
	AuthAdminUser     string
	AuthAdminPassword string
	SessionTTL        time.Duration
	CookieName        string
	CookieSecure      bool
	TrustProxy        bool
	// Brute-force protection.
	LoginMaxFailures int
	LoginWindow      time.Duration
	LoginLockout     time.Duration
	// IP access.
	IPAllowlistOnly bool
}

// Catalogue exports of the LOLBAS and GTFOBins projects.
const (
	DefaultLOLBASURL   = "https://lolbas-project.github.io/api/lolbas.json"
	DefaultGTFOBinsURL = "https://gtfobins.org/api.json"
)

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

func envInt(key string, def int) (int, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(env(key, ""))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

// ParsePrefixes parses a comma-separated list of CIDRs or single IPs.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			addr, err := netip.ParseAddr(part)
			if err != nil {
				return nil, fmt.Errorf("bad local network %q: %w", part, err)
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("bad local network %q: %w", part, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// DefaultThreatFeeds are free, bulk-downloadable IP/CIDR lists (no API keys, no per-IP quotas).
// abuse.ch retired the SSLBL IP blacklist on 2025-01-03; ThreatFox (ip:port IOCs, botnet C2s)
// is its successor and also covers Feodo Tracker's data when that site is down.
const DefaultThreatFeeds = "feodo=https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt," +
	"threatfox=https://threatfox.abuse.ch/export/csv/ip-port/recent/," +
	"spamhaus_drop=https://www.spamhaus.org/drop/drop.txt," +
	"tor_exits=https://check.torproject.org/torbulkexitlist," +
	"cins=https://cinsscore.com/list/ci-badguys.txt," +
	"et_compromised=https://rules.emergingthreats.net/blockrules/compromised-ips.txt," +
	"blocklist_de=https://lists.blocklist.de/lists/all.txt"

// ParseFeeds parses "name=url,name=url" (also accepts newline separators).
func ParseFeeds(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, url, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(name)] = strings.TrimSpace(url)
	}
	return out
}

// IsGateway reports whether the address is a configured gateway/router.
func (c *Config) IsGateway(a netip.Addr) bool {
	for _, g := range c.Gateways {
		if g == a.Unmap() {
			return true
		}
	}
	return false
}

// DefaultLocalNetworks are RFC1918 + loopback + link-local + ULA.
const DefaultLocalNetworks = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,fc00::/7,fe80::/10,::1/128"

// Load reads configuration from the environment.
func Load() (*Config, error) {
	c := &Config{
		ListenAddr:    env("LISTEN_ADDR", ":8080"),
		TLSListenAddr: env("TLS_LISTEN_ADDR", ""),
		TLSCertFile:   env("TLS_CERT_FILE", ""),
		AgentDistDir:  env("AGENT_DIST_DIR", "/app/agent"),
		TLSKeyFile:    env("TLS_KEY_FILE", ""),
		DatabaseURL:   env("DATABASE_URL", "postgres://pmacct:pmacctpass@10.0.0.210:55432/pmacct?sslmode=disable"),
		StaticDir:     env("STATIC_DIR", "../frontend/dist"),
		EnrichEnabled: envBool("ENRICH_ENABLED", true),
		IPAPIBaseURL:  env("IPAPI_BASE_URL", "http://ip-api.com"),
		IPInfoToken:   env("IPINFO_TOKEN", ""),
		IPInfoBaseURL: env("IPINFO_BASE_URL", "https://ipinfo.io"),
		ReverseDNS:    envBool("ENRICH_REVERSE_DNS", true),
		VTAPIKey:      env("VT_API_KEY", ""),
		VTBaseURL:     env("VT_BASE_URL", "https://www.virustotal.com"),
	}
	var err error
	if c.LocalNetworks, err = ParsePrefixes(env("LOCAL_NETWORKS", DefaultLocalNetworks)); err != nil {
		return nil, err
	}
	if c.EnrichInterval, err = envDuration("ENRICH_INTERVAL", 5*time.Minute); err != nil {
		return nil, err
	}
	if c.EnrichRefreshAfter, err = envDuration("ENRICH_REFRESH_AFTER", 7*24*time.Hour); err != nil {
		return nil, err
	}
	if c.EnrichBatchSize, err = envInt("ENRICH_BATCH_SIZE", 200); err != nil {
		return nil, err
	}
	// ip-api.com free tier allows 45 req/min; 1.5s keeps us safely under.
	if c.EnrichRateLimit, err = envDuration("ENRICH_RATE_LIMIT", 1500*time.Millisecond); err != nil {
		return nil, err
	}
	if c.EnrichLookbackWindow, err = envDuration("ENRICH_LOOKBACK", 24*time.Hour); err != nil {
		return nil, err
	}
	if c.HTTPTimeout, err = envDuration("HTTP_TIMEOUT", 10*time.Second); err != nil {
		return nil, err
	}
	if c.VTRateLimit, err = envDuration("VT_RATE_LIMIT", 15*time.Second); err != nil {
		return nil, err
	}
	if c.VTDailyQuota, err = envInt("VT_DAILY_QUOTA", 500); err != nil {
		return nil, err
	}
	if c.VTMonthlyQuota, err = envInt("VT_MONTHLY_QUOTA", 15500); err != nil {
		return nil, err
	}
	if c.VTRefreshAfter, err = envDuration("VT_REFRESH_AFTER", 7*24*time.Hour); err != nil {
		return nil, err
	}
	if c.VTBatchSize, err = envInt("VT_BATCH_SIZE", 100); err != nil {
		return nil, err
	}
	c.AbuseIPDBKey = env("ABUSEIPDB_KEY", "")
	c.AbuseIPDBBaseURL = env("ABUSEIPDB_BASE_URL", "https://api.abuseipdb.com")
	if c.AbuseIPDBRateLimit, err = envDuration("ABUSEIPDB_RATE_LIMIT", 2*time.Second); err != nil {
		return nil, err
	}
	if c.AbuseIPDBDailyQuota, err = envInt("ABUSEIPDB_DAILY_QUOTA", 1000); err != nil {
		return nil, err
	}
	if c.AbuseIPDBRefresh, err = envDuration("ABUSEIPDB_REFRESH_AFTER", 7*24*time.Hour); err != nil {
		return nil, err
	}
	c.GreyNoiseKey = env("GREYNOISE_KEY", "")
	c.GreyNoiseBaseURL = env("GREYNOISE_BASE_URL", "https://api.greynoise.io")
	if c.GreyNoiseRateLimit, err = envDuration("GREYNOISE_RATE_LIMIT", 2*time.Second); err != nil {
		return nil, err
	}
	if c.GreyNoiseDailyQuota, err = envInt("GREYNOISE_DAILY_QUOTA", 50); err != nil {
		return nil, err
	}
	if c.GreyNoiseRefresh, err = envDuration("GREYNOISE_REFRESH_AFTER", 14*24*time.Hour); err != nil {
		return nil, err
	}
	c.OTXKey = env("OTX_KEY", "")
	c.OTXBaseURL = env("OTX_BASE_URL", "https://otx.alienvault.com")
	if c.OTXRateLimit, err = envDuration("OTX_RATE_LIMIT", 1*time.Second); err != nil {
		return nil, err
	}
	if c.OTXDailyQuota, err = envInt("OTX_DAILY_QUOTA", 10000); err != nil {
		return nil, err
	}
	if c.OTXRefresh, err = envDuration("OTX_REFRESH_AFTER", 14*24*time.Hour); err != nil {
		return nil, err
	}
	c.GeoIPCityDB = env("GEOIP_CITY_DB", "")
	c.GeoIPASNDB = env("GEOIP_ASN_DB", "")

	c.ThreatFeeds = ParseFeeds(env("THREAT_FEEDS", DefaultThreatFeeds))
	if c.ThreatFeedsInterval, err = envDuration("THREAT_FEEDS_INTERVAL", time.Hour); err != nil {
		return nil, err
	}
	c.LOLBASURL = env("LOLBAS_URL", DefaultLOLBASURL)
	c.GTFOBinsURL = env("GTFOBINS_URL", DefaultGTFOBinsURL)
	c.FileIntelEnabled = envBool("FILE_INTEL", true)
	if c.FileVTRefreshAfter, err = envDuration("FILE_VT_REFRESH_AFTER", 30*24*time.Hour); err != nil {
		return nil, err
	}
	c.MHREnabled = envBool("MHR_ENABLED", true)
	c.RulesEnabled = envBool("RULES_ENABLED", true)
	if c.RulesInterval, err = envDuration("RULES_INTERVAL", time.Minute); err != nil {
		return nil, err
	}
	for _, g := range strings.Split(env("GATEWAYS", ""), ",") {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		a, err := netip.ParseAddr(g)
		if err != nil {
			return nil, fmt.Errorf("GATEWAYS: %w", err)
		}
		c.Gateways = append(c.Gateways, a)
	}
	c.SuricataListen = env("SURICATA_LISTEN", "")

	c.NotifyWebhookURL = env("NOTIFY_WEBHOOK_URL", "")
	c.NotifyNtfyURL = env("NOTIFY_NTFY_URL", "")
	c.NotifyNtfyToken = env("NOTIFY_NTFY_TOKEN", "")
	c.NotifyGotifyURL = env("NOTIFY_GOTIFY_URL", "")
	c.NotifyGotifyToken = env("NOTIFY_GOTIFY_TOKEN", "")
	c.NotifyTelegramToken = env("NOTIFY_TELEGRAM_TOKEN", "")
	c.NotifyTelegramChat = env("NOTIFY_TELEGRAM_CHAT_ID", "")
	c.NotifySlackWebhook = env("NOTIFY_SLACK_WEBHOOK_URL", "")
	c.NotifySMTPHost = env("NOTIFY_SMTP_HOST", "")
	if c.NotifySMTPPort, err = envInt("NOTIFY_SMTP_PORT", 587); err != nil {
		return nil, err
	}
	c.NotifySMTPUser = env("NOTIFY_SMTP_USER", "")
	c.NotifySMTPPass = env("NOTIFY_SMTP_PASS", "")
	c.NotifySMTPFrom = env("NOTIFY_SMTP_FROM", "")
	c.NotifySMTPTo = env("NOTIFY_SMTP_TO", "")
	c.NotifyMinSeverity = env("NOTIFY_MIN_SEVERITY", "critical") // overridable at runtime on the Enrichment page
	if c.NotifyDigest, err = envDuration("NOTIFY_DIGEST", 0); err != nil {
		return nil, err
	}
	c.NotifyQuietHours = env("NOTIFY_QUIET_HOURS", "")
	if c.NotifyRenotifyAfter, err = envDuration("NOTIFY_RENOTIFY_AFTER", 24*time.Hour); err != nil {
		return nil, err
	}
	c.PublicURL = strings.TrimRight(env("PUBLIC_URL", ""), "/")
	for _, h := range strings.Split(env("TLS_HOSTS", ""), ",") {
		if h = strings.TrimSpace(h); h != "" {
			c.TLSHosts = append(c.TLSHosts, h)
		}
	}

	c.AuthEnabled = envBool("AUTH_ENABLED", true)
	c.AuthAdminUser = env("AUTH_ADMIN_USER", "admin")
	c.AuthAdminPassword = env("AUTH_ADMIN_PASSWORD", "admin")
	if c.SessionTTL, err = envDuration("SESSION_TTL", 7*24*time.Hour); err != nil {
		return nil, err
	}
	c.CookieName = env("AUTH_COOKIE_NAME", "pa_session")
	c.CookieSecure = envBool("AUTH_COOKIE_SECURE", strings.HasPrefix(c.PublicURL, "https://"))
	c.TrustProxy = envBool("TRUST_PROXY", false)
	if c.LoginMaxFailures, err = envInt("LOGIN_MAX_FAILURES", 5); err != nil {
		return nil, err
	}
	if c.LoginWindow, err = envDuration("LOGIN_WINDOW", 15*time.Minute); err != nil {
		return nil, err
	}
	if c.LoginLockout, err = envDuration("LOGIN_LOCKOUT", 15*time.Minute); err != nil {
		return nil, err
	}
	c.IPAllowlistOnly = envBool("AUTH_IP_ALLOWLIST_ONLY", false)
	return c, nil
}

// LocalNetworksCIDR returns the local networks as strings for SQL usage.
func (c *Config) LocalNetworksCIDR() []string {
	out := make([]string, 0, len(c.LocalNetworks))
	for _, p := range c.LocalNetworks {
		out = append(out, p.String())
	}
	return out
}

// IsLocal reports whether the address falls into a configured local network.
func (c *Config) IsLocal(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range c.LocalNetworks {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
