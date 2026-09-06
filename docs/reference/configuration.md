# Configuration

Everything is configured by environment variables (compose: `deploy/analyzer.env`). The
**complete, always-current list** lives in
[`README.md`](https://github.com/vlastee/Pmacct-Suricata-Analyzer/blob/master/README.md#configuration-environment)
and the annotated
[`.env.example`](https://github.com/vlastee/Pmacct-Suricata-Analyzer/blob/master/.env.example).
The ones you will actually touch:

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | compose-internal | PostgreSQL with the pmacct `acct` table |
| `LISTEN_ADDR` | `:8080` (compose maps `:8090`) | HTTP UI/API |
| `TLS_LISTEN_ADDR` / `TLS_HOSTS` | – | HTTPS with the built-in internal CA; **required for agents** |
| `LOCAL_NETWORKS` | RFC1918 + loopback + ULA | what counts as *local*; add your WAN IP if exporting on WAN |
| `VT_API_KEY` | – | VirusTotal IP + file lanes |
| `ABUSEIPDB_KEY` / `GREYNOISE_KEY` | – | reputation lanes |
| `GEOIP_CITY_DB` / `GEOIP_ASN_DB` | – | local MaxMind `.mmdb` instead of ip-api |
| `THREAT_FEEDS` / `THREAT_FEEDS_INTERVAL` | abuse.ch, Spamhaus, … / `1h` | bulk threat lists |
| `LOLBAS_URL` / `GTFOBINS_URL` | project exports | abusable-binaries catalogues (empty disables) |
| `FILE_INTEL` / `MHR_ENABLED` / `FILE_VT_REFRESH_AFTER` | `true` / `true` / `720h` | hash look-ups for agent-reported programs |
| `SURICATA_LISTEN` | – | EVE syslog listener, e.g. `:5514` |
| `RULES_ENABLED` / `RULES_INTERVAL` | `true` / `1m` | detection engine |
| `GATEWAYS` | – | router IPs exempt from DNS/beaconing rules |
| `NOTIFY_MIN_SEVERITY` | `critical` | minimum severity delivered (changeable in the UI) |
| `NOTIFY_TELEGRAM_*`, `NOTIFY_NTFY_URL`, `NOTIFY_SMTP_*`, … | – | notification channels |
| `AUTH_ADMIN_USER` / `AUTH_ADMIN_PASSWORD` | `admin`/`admin` | first account; default password forces a change |
| `PUBLIC_URL` | – | base URL used in notification links |

!!! tip
    Secrets belong in `analyzer.env` / `.env` — both are in `.gitignore`. Never put keys in
    compose files or code.
