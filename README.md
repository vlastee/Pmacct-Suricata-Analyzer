# Pmacct Analyzer

An ntopng-style traffic analyzer for data collected by [pmacct](http://www.pmacct.net/) into PostgreSQL.
It reads the `acct` table pmacct writes to, adds enrichment about every external IP address
(reverse DNS, geolocation, ASN/organisation, VirusTotal / AbuseIPDB / GreyNoise reputation), keeps
that data fresh, **detects malicious behaviour with a rules engine**, matches traffic against
**threat-intelligence feeds**, optionally ingests **Suricata IDS** alerts, raises deduplicated
**alerts** with **notifications**, and presents everything in a web UI.

```
┌──────────┐  writes  ┌──────────────────────┐  reads   ┌───────────────────────────┐  JSON  ┌───────────────┐
│  pmacct  │ ───────► │ PostgreSQL           │ ◄──────► │ Go API + workers + rules  │ ◄────► │ Svelte web UI │
└──────────┘          │ acct, ip_info,       │          │  (backend/)               │        │ (frontend/)   │
                      │ alerts, threat_lists,│          └───┬─────────────┬─────────┘        └───────────────┘
   Suricata EVE ─────►│ ids_events, rollups… │              │ enrichment  │ notifications
   (syslog, optional) └──────────────────────┘   ip-api/ipinfo/MaxMind · VT/AbuseIPDB/GreyNoise ·
                                                  threat feeds (abuse.ch, Spamhaus, Tor…) · ntfy/Telegram/…
```

## Layout

| Path | What |
|---|---|
| `backend/` | Go 1.26 module: HTTP API, SQL analytics, enrichment, rules engine, feeds, notifications, Suricata ingest |
| `backend/internal/rules/` | Detection rules engine (thresholds tunable in the UI) |
| `backend/internal/db/migrations/` | Schema the analyzer adds to the pmacct database (never modifies pmacct's tables) |
| `backend/integration/` | Integration tests (real PostgreSQL in Podman + mocked ip-api / VirusTotal / feeds / Suricata) |
| `frontend/` | Svelte 5 + TypeScript + Vite single-page app |
| `scripts/integration-test.sh` | Fully automated Podman test pipeline (unit → integration → container e2e) |
| `Containerfile`, `compose.yaml` | Multi-stage image (frontend build → Go build → alpine runtime) |

## Quick start

```sh
cp .env.example .env          # edit DATABASE_URL / LOCAL_NETWORKS / API keys
make build                    # builds frontend/dist and backend/bin/server
make run                      # http://localhost:8080
```

Or as a container:

```sh
podman compose up -d --build  # or: make image && podman run --env-file .env -p 8080:8080 localhost/pmacct-analyzer
```

Development (hot reload): `make dev-api` in one terminal, `make dev-web` in another (Vite on :5173 proxies `/api` to :8080).

### Deploying the whole stack (one compose)

[`deploy/`](deploy/) contains a **self-contained** compose that brings up PostgreSQL, pmacct
`nfacctd`, the retention job, and the analyzer together — one `docker compose up` and everything
sits in this repo:

```sh
cd deploy
cp analyzer.env.example analyzer.env     # then put VT_API_KEY etc. in it
docker compose up -d --build
```

All services use `network_mode: host`, so on the collector (10.0.0.210): PostgreSQL on `:55432`,
`nfacctd` NetFlow on UDP `:2055` (point pfSense/softflowd here), the UI on `http://10.0.0.210:8090`,
and the Suricata EVE syslog listener on `:5514`. pmacct's config lives in
[`deploy/nfacctd.conf`](deploy/nfacctd.conf) and the schema in [`deploy/initdb/`](deploy/initdb/)
(runs only on a fresh `postgres_data`; the analyzer adds its own tables at runtime and never
touches pmacct's). To keep existing data, drop your current `postgres_data` into `deploy/`.

### Adding the analyzer to an existing pmacct stack

If you already run pmacct-postgres / nfacctd yourself, paste the `analyzer` service from
[`deploy/compose.collector-host.yaml`](deploy/compose.collector-host.yaml) into your compose
instead (same settings, `network_mode: host`, builds from a checkout of this repo).

Notes for either setup:

* The analyzer only adds tables/indexes; `nfacctd.conf` and the pmacct schema stay untouched.
  The `acct(stamp_inserted)` index it creates also makes the nightly retention `DELETE` cheap.
* Retention only trims `acct`; `ip_info` (enrichment) and `ip_nicknames` are kept forever and are
  small (one row per IP).
* To see *which internal device* talked to an external IP, softflowd on pfSense must export from
  the **LAN** interface(s), not WAN — WAN flows are post-NAT and only ever show the router's
  public address. Select LAN only (not LAN + WAN, which double-counts every connection).

### Updating a running deployment

Pull the new code and rebuild **only the analyzer** — the database, `nfacctd` and retention keep
running, so collection never stops and no data is touched:

```sh
cd Pmacct-Suricata-Analyzer
git pull                                   # or rsync the checkout from your workstation
cd deploy
docker compose up -d --build analyzer
docker compose logs -f analyzer            # Ctrl-C to stop following
```

* `--build` rebuilds the image from the new source (multi-stage, so the host needs no Go/Node);
  `up -d` then recreates just the container whose image changed.
* Schema migrations run automatically at startup — there is never a separate DB-upgrade step.
* `postgres_data/`, `analyzer.env` and `.env` are git-ignored, so neither `git pull` nor
  `rsync --delete` (with `--filter=':- .gitignore'`) can overwrite data or secrets.
* If `deploy/docker-compose.yaml` itself changed (new service, new env var), drop the `analyzer`
  argument so every service is reconciled: `docker compose up -d --build`.
* Changed `analyzer.env`? `docker compose up -d analyzer` (no `--build`) recreates the container
  with the new values — a plain `restart` does **not** re-read the env file.
* Optional: `docker image prune -f` removes the superseded image layers.

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `postgres://pmacct:pmacctpass@10.0.0.210:55432/pmacct?sslmode=disable` | pmacct database |
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `STATIC_DIR` | `../frontend/dist` | built SPA to serve |
| `LOCAL_NETWORKS` | RFC1918 + loopback + link-local + ULA | Comma-separated CIDRs/IPs treated as *local*. **Add the pmacct host's own public address if it captures on the WAN side** (e.g. `174.54.200.232/32` for this deployment), otherwise all traffic looks external. |
| `ENRICH_ENABLED` | `true` | run the background enrichment workers |
| `ENRICH_INTERVAL` | `5m` | how often each lane scans for work |
| `ENRICH_LOOKBACK` | `24h` | only IPs seen in traffic within this window are (re)enriched — "the daily feed" |
| `ENRICH_REFRESH_AFTER` | `168h` | geo/ASN records older than this are refreshed if the IP is still seen |
| `ENRICH_BATCH_SIZE` / `ENRICH_RATE_LIMIT` | `200` / `1500ms` | per pass / between lookups (ip-api free tier is 45 req/min) |
| `ENRICH_REVERSE_DNS` | `true` | PTR lookups when the provider gave no hostname |
| `IPAPI_BASE_URL` | `http://ip-api.com` | geo provider (no key needed) |
| `IPINFO_TOKEN` | – | when set, ipinfo.io is used instead of ip-api.com |
| `VT_API_KEY` | – | enables the VirusTotal lane. **Put it in `.env`** (git-ignored) — never in code or compose files. |
| `VT_RATE_LIMIT` / `VT_DAILY_QUOTA` / `VT_MONTHLY_QUOTA` | `15s` / `500` / `15500` | VirusTotal *standard free public API* limits (4 lookups/min, 500/day, 15.5 K/month). Lower them if you share the key with other tools. |
| `VT_REFRESH_AFTER` | `168h` | re-check an IP's reputation after this, if it is still seen in traffic |
| `VT_BATCH_SIZE` | `100` | max VT lookups per pass (also capped by remaining daily quota) |
| `ABUSEIPDB_KEY` / `GREYNOISE_KEY` | – | enable the AbuseIPDB (1000/day) / GreyNoise reputation lanes |
| `GEOIP_CITY_DB` / `GEOIP_ASN_DB` | – | MaxMind GeoLite2 `.mmdb` paths; used for geo instead of ip-api when both set |
| `RULES_ENABLED` / `RULES_INTERVAL` | `true` / `1m` | run the detection rules engine and how often |
| `GATEWAYS` | – | router IP(s), exempt from DNS/beaconing rules (e.g. `10.0.0.1`) |
| `THREAT_FEEDS` | abuse.ch, Spamhaus, Tor, CINS, … | `name=url,…` bulk IP/CIDR feeds (empty disables) |
| `THREAT_FEEDS_INTERVAL` | `1h` | how often feeds are refreshed |
| `SURICATA_LISTEN` | – | syslog listen address for Suricata EVE (e.g. `:5514`); empty disables |
| `NOTIFY_MIN_SEVERITY` | `warning` | minimum severity delivered to notification channels |
| `NOTIFY_DIGEST` / `NOTIFY_QUIET_HOURS` / `NOTIFY_RENOTIFY_AFTER` | `0` / – / `24h` | batch window / silent hours (`23-7`) / re-notify interval |
| `NOTIFY_NTFY_URL`, `NOTIFY_GOTIFY_*`, `NOTIFY_TELEGRAM_*`, `NOTIFY_SLACK_WEBHOOK_URL`, `NOTIFY_WEBHOOK_URL`, `NOTIFY_SMTP_*` | – | notification channels (configure any subset) |
| `PUBLIC_URL` | – | base URL used in notification links |
| `AUTH_ENABLED` | `true` | require login for the UI/API; `false` leaves it fully open |
| `AUTH_ADMIN_USER` / `AUTH_ADMIN_PASSWORD` | `admin` / `admin` | seeds the first account on an empty DB; the default `admin` password forces a change on first login |
| `SESSION_TTL` | `168h` | session lifetime |
| `LOGIN_MAX_FAILURES` / `LOGIN_WINDOW` / `LOGIN_LOCKOUT` | `5` / `15m` / `15m` | brute-force: this many failures from one IP in the window locks it out for the lockout period |
| `TRUST_PROXY` | `false` | honour `X-Forwarded-For` for the client IP (enable only behind a trusted proxy) |
| `AUTH_COOKIE_SECURE` | auto (https) | mark the session cookie `Secure` |
| `AUTH_IP_ALLOWLIST_ONLY` | `false` | when allow rules exist, permit only listed IPs |
| `LOG_LEVEL` | `info` | `debug` logs every API request |

The full annotated list, with the reputation/feed/notification blocks, is in [`.env.example`](.env.example).

## Enrichment strategy

Two independent lanes run inside the API process and share the `ip_info` table:

* **geo lane** (ip-api.com, ipinfo.io, or **local MaxMind GeoLite2** + reverse DNS): hostname,
  country/region/city, coordinates, ASN, organisation, ISP, hosting/proxy/mobile flags.
* **VirusTotal lane**: malicious/suspicious/harmless/undetected engine counts, reputation, tags, network.
* **AbuseIPDB** and **GreyNoise** lanes (optional, same quota-aware scheduler) add a confidence
  score / scanner classification per IP.

If `GEOIP_CITY_DB` and `GEOIP_ASN_DB` point at MaxMind `.mmdb` files (pfBlockerNG already downloads
these on pfSense), the geo lane uses them instead of ip-api.com — no network, no quota.

Both lanes pick candidates the same quota-efficient way, so the expensive VirusTotal budget is
spent where it matters:

1. only external IPs that appeared in traffic within `ENRICH_LOOKBACK` (default: the last 24 h);
2. **never-looked-up IPs first**, largest traffic volume first;
3. then records older than the refresh interval that *still* appear in the feed;
4. failed lookups are retried with exponential backoff; a VirusTotal `429` stops the pass
   immediately and the IP is not recorded, so it is first in line next time.

The daily and monthly VirusTotal counts are derived from `vt_lookup_at` timestamps in the database,
so a restart never overspends the quota; each pass spends at most `min(daily left, monthly left,
VT_BATCH_SIZE)` lookups. Multicast, broadcast, CGNAT and local addresses are never sent out.

> The free VirusTotal key is licensed for personal, non-commercial use only. The key lives in `.env`;
> keep that file out of version control (it already is in `.gitignore`).

## Detection & alerting

A **rules engine** (`RULES_ENABLED`, default on) evaluates a set of detections every
`RULES_INTERVAL` over recent traffic and turns findings into **alerts** — deduplicated one-per
`(rule, host, peer[, port])`, with a first/last-seen window, a count, and a state
(*open → acked → resolved*). Alerts drive the nav badge, the **Alerts** page (ack / resolve /
filter), per-host risk scores, and notifications. Every rule is tunable in the **Rules** page
(thresholds, severity, disable, or exempt trusted hosts by IP/nickname); "Run now" evaluates
immediately.

Built-in rules:

| Rule | Fires when |
|---|---|
| `threat_feed` | A local host exchanges traffic with an IP on a threat feed (C2, Tor, spam/attack source). **critical** |
| `reputation` | Traffic with an IP flagged by VirusTotal (≥ N engines), AbuseIPDB or GreyNoise |
| `suspicious_port` | Outbound to Telnet/SMB/RDP/SMTP/IRC/VNC… (mining pools & Tor ports → critical) |
| `port_scan` / `host_scan` | One source hits many ports on a target, or many hosts, with tiny (SYN-only) flows |
| `brute_force` | An external IP opens many short connections to one exposed local service |
| `one_way` | A host has many unanswered outbound peers; unanswered attempts to *flagged* peers → critical (malware whose callbacks pfSense is blocking) |
| `dns_resolver` / `dns_volume` | DNS sent to a resolver other than the router; or abnormally high DNS volume (tunnelling/DGA) |
| `geo_policy` | Traffic with a watched country (opt-in: set `countries`) |
| `volume_anomaly` | A host's hourly upload far exceeds its own baseline for that hour-of-day (median + N×MAD) |
| `new_host` / `new_destination` | A new device appears; or a host contacts a never-before-seen ASN that is hosting/proxy/listed/flagged |
| `beaconing` | Regular, constant-size contact to one peer — the classic C2 heartbeat |
| `long_lived` | A multi-hour connection to a hosting/VPN address (tunnel / persistent C2) |
| `iot_fanout` | A device tagged **iot** talks to an unusually large number of ASNs |
| `ids` | Wraps Suricata alerts (see below) into the same alert stream |

**Threat feeds** (`THREAT_FEEDS`, refreshed every `THREAT_FEEDS_INTERVAL`) are bulk IP/CIDR lists
matched entirely locally — no per-IP quota. The default set is abuse.ch Feodo & SSLBL, Spamhaus
DROP, the Tor exit list, CINS, ET compromised, and blocklist.de. Because pmacct captures on the
LAN *before* pfSense drops a packet, a **blocked** outbound attempt to a C2 still shows up as a
one-way flow — so `threat_feed` + `one_way` catch malware even when the firewall stops it.

**Notifications**: alerts at or above `NOTIFY_MIN_SEVERITY` are delivered to any configured
channel — ntfy, Gotify, Telegram, Slack, a generic JSON webhook, or SMTP email. Supports immediate
or digest delivery (`NOTIFY_DIGEST`), quiet hours (`NOTIFY_QUIET_HOURS`), and a re-notify interval.
"Send test" on the Enrichment page verifies delivery. New alerts are never lost during quiet hours —
they're recorded and delivered when the window ends.

Per-host **rollups** (`host_hourly`, `host_peer_daily`) are maintained by the worker and kept for
months, so baselines and "new destination" survive the 7-day raw-flow retention.

## Authentication & access control

The UI and API require login (`AUTH_ENABLED=true`, the default). On an empty database a single
**admin** account is seeded from `AUTH_ADMIN_USER` / `AUTH_ADMIN_PASSWORD` (default `admin` / `admin`);
using the default password **forces a password change on first login** before anything else works.
Sessions are server-side (revocable), carried in an HttpOnly cookie; passwords are bcrypt-hashed.

- **Brute-force protection**: failed logins are tracked per IP. After `LOGIN_MAX_FAILURES` within
  `LOGIN_WINDOW`, that IP is auto-locked for `LOGIN_LOCKOUT` — it gets `429 Retry-After` on the login
  page and `403` everywhere else. bcrypt is always evaluated (even for unknown users) to avoid
  timing/user-enumeration, and an allow-listed IP is never auto-blocked.
- **IP access control**: the **Security** page (admin only) shows login activity and per-IP attempt
  counts (filterable by IP / user / result), lets you **block/unblock** any IP or CIDR, and lists the
  allow/deny rules (manual entries and expiring auto lockouts). A manual `deny` blocks the whole app;
  set `AUTH_IP_ALLOWLIST_ONLY=true` to permit only allow-listed addresses.
- **Users**: admins can add users (each forced to set their own password first), disable/enable,
  reset a password, or delete — from the Security page.
- Behind a reverse proxy, set `TRUST_PROXY=true` so the real client IP is taken from
  `X-Forwarded-For` (otherwise blocking/lockout would key on the proxy's address). Serve over HTTPS
  (`PUBLIC_URL=https://…` or `AUTH_COOKIE_SECURE=true`) so the cookie is marked `Secure`.

> With `network_mode: host`, `TRUST_PROXY` should stay `false` — the analyzer sees the real source IP
> directly. Change the default admin password immediately; `AUTH_ENABLED=false` disables all of the
> above and should only be used on a trusted, isolated network.

## Suricata IDS (optional)

Set `SURICATA_LISTEN` (e.g. `:5514`) and the analyzer listens for Suricata **EVE JSON** over syslog
(UDP + TCP). Events are stored, shown on the **IDS** page and per-host, and folded into the alert
stream (Suricata severity 1 → critical, 2 → warning, 3+ → info; tunable via the `ids` rule).
Enabling the **dns** and **tls** EVE types additionally teaches the analyzer real hostnames (DNS
answers, TLS SNI), shown next to IPs everywhere.

The **IDS** page shows what actually arrives: listener health (receiving / quiet-for / last error),
a per-event-type table (`alert`, `dns.answer`, `dns.query`, `tls`, … with what each is used for and
which are ignored), the malformed/truncated counter, and every stored alert with its raw EVE record
one click away. Alerts raised from Suricata link back to the exact event (`ids_event_id`), and
`GET /api/v1/ids/events/{id}` returns it with the full JSON.

pfSense setup: install the **suricata** package, add it on the **LAN** interface (pre-NAT, so
alerts name the device), enable **ET Open** rules, and in the interface's *EVE Output Settings*
choose **SYSLOG** with logged types *alert* (+ optionally *dns*, *tls*), packet/payload logging
**off**. Then *Status → System Logs → Settings → Remote Logging* → `COLLECTOR_IP:5514`. Run in
IDS (alert-only) mode first and tune noisy signatures before considering blocking. If the container
is bridged, map the port (`-p 5514:5514/udp`).

## HTTP API

All endpoints accept `since` / `until` (RFC3339, unix seconds, or a relative duration like `24h`; default = last 24 h).

| Endpoint | Description |
|---|---|
| `GET /healthz` | liveness (checks the DB) |
| `GET /api/v1/meta` | local networks, data range |
| `GET /api/v1/overview` | totals, time series, top protocols/ports/hosts/countries, flagged IPs |
| `GET /api/v1/timeseries?interval=5m&ip=` | bucketed in/out bytes |
| `GET /api/v1/hosts?scope=local\|external&sort=&q=&country=&asn=&limit=&offset=` | per-host summary with enrichment |
| `GET /api/v1/hosts/{ip}` | host detail: peers, ports, time series, enrichment |
| `GET /api/v1/flows?ip=&port=&proto=&limit=&offset=` | raw accounting rows |
| `GET /api/v1/groups/{country\|asn\|org\|isp}` | external traffic grouped by enrichment dimension |
| `GET /api/v1/threats` | external IPs in the window flagged by VirusTotal |
| `GET /api/v1/nicknames?q=` · `GET/PUT/DELETE /api/v1/nicknames/{ip}` | user nicknames for any IP (`PUT` body: `{"nickname": "...", "note": "..."}`) |
| `GET /api/v1/ips?q=` · `GET /api/v1/ips/{ip}` · `GET /api/v1/ips/{ip}/names` · `POST /api/v1/ips/{ip}/refresh` | enrichment records, observed names |
| `GET /api/v1/enrichment/status` · `POST /api/v1/enrichment/run[?wait=1]` | worker/lane status / trigger a pass |
| `GET /api/v1/alerts?state=&severity=&rule=&host=` · `GET /api/v1/alerts/summary` | list / summarise alerts |
| `POST /api/v1/alerts/{id}/{ack\|resolve\|reopen}` · `POST /api/v1/alerts/resolve?rule=&host=` | change alert state |
| `GET /api/v1/rules` · `PUT /api/v1/rules/{name}` · `POST /api/v1/rules/{name}/run` | list / configure / run a rule |
| `GET /api/v1/ids/events?ip=&sid=` · `GET /api/v1/ids/summary` | Suricata events / per-signature summary |
| `GET /api/v1/system/status` · `POST /api/v1/notify/test` | feeds, lanes, IDS, notification status / send a test |

## Tests

```sh
make unit          # Go unit tests + svelte-check
make integration   # scripts/integration-test.sh — needs only podman, go, curl
make test          # both
```

`scripts/integration-test.sh` is fully automated:

1. starts a throwaway `postgres:16-alpine` container on a random port;
2. runs the Go integration suite against it — the pmacct schema and a deterministic fixture are
   loaded, migrations applied twice (idempotency), and every endpoint, the classification of
   local/external traffic, the geo & VirusTotal lanes (ordering, staleness, daily/monthly quotas,
   429 handling), nicknames/kinds, the **rules engine + alert lifecycle** (raise → dedupe → ack →
   resolve → re-raise, risk scores, config validation), **threat-list matching**, **Suricata EVE
   ingest** (alerts, DNS/TLS name learning), **reputation** and **rollups** are exercised against
   mock ip-api / VirusTotal / Suricata / webhook servers;
3. builds the production container image, runs it on a Podman network next to the database,
   and checks the served SPA, static assets, API answers and the in-container health check.

Everything is cleaned up on exit (`--keep` retains the containers, `--no-e2e` skips step 3).

## Database changes

The analyzer only *adds* to the pmacct database (migrations are tracked in `schema_migrations`):

* `ip_info` — one row per external IP with geo/ASN and VirusTotal columns;
* `ip_nicknames` — user-assigned names/notes/kind for local or external IPs (shown everywhere, searchable);
* `alerts` — deduplicated detections with state and history;
* `host_hourly`, `host_peer_daily` — per-host rollups for baselines (kept ~6 months / 60 days);
* `threat_lists` — bulk feed entries, GiST-indexed for fast CIDR containment matching;
* `ids_events` — Suricata alerts; `ip_names` — hostnames observed via DNS/TLS/rDNS;
* `ip_reputation` — AbuseIPDB/GreyNoise verdicts; `settings` — rule configuration & job cursors;
* indexes on `acct(stamp_inserted)`, `acct(ip_src)`, `acct(ip_dst)` to keep window queries fast
  (~0.7 s for a 1 h window on a 4.8 M-row table without them being warm; this also makes the
  existing retention `DELETE` much cheaper).

pmacct's own tables (`acct`, `acct_as`, `acct_uni`, `proto`) are never modified.
