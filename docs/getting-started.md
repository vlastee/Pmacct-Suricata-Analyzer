# Getting started

This walks you from a clean Linux box to a running analyzer with the UI open. You need Docker
(or Podman) with the compose plugin, and a router that can export NetFlow (see the
[pfSense tutorial](tutorials/pfsense.md) — any softflowd/NetFlow v5/v9/sFlow source works).

## 1. Get the code and configure

```bash
git clone https://github.com/vlastee/Pmacct-Suricata-Analyzer.git
cd Pmacct-Suricata-Analyzer/deploy
cp ../.env.example analyzer.env    # then edit it
```

The one setting you must get right is **`LOCAL_NETWORKS`**: comma-separated CIDRs the analyzer
treats as *local*. RFC1918 + loopback + link-local are built in; **add your WAN address if the
exporter captures on the WAN side**, otherwise all your own traffic looks external.

Secrets (VirusTotal key, Telegram token, …) go into `analyzer.env` / `.env` — both are
git-ignored.

## 2. Start the stack

```bash
docker compose up -d --build
docker compose ps          # postgres, nfacctd, analyzer — all healthy
docker compose logs -f analyzer
```

The first build takes a while: it compiles the Go backend, the Svelte frontend and
cross-compiles the endpoint agent for Linux (static musl) and Windows (mingw). Add
`--build-arg WITH_AGENT=0` to skip the agent stage if you do not need it.

## 3. Log in

Open `http://<server>:8090`. The first account is seeded from
`AUTH_ADMIN_USER` / `AUTH_ADMIN_PASSWORD` (default `admin` / `admin`) and the default password
**forces a change on first login**.


## 4. Send it traffic

- **NetFlow**: point softflowd (or any NetFlow exporter) at the `nfacctd` port —
  see [pfSense: NetFlow & Suricata](tutorials/pfsense.md). Within a couple of minutes the
  Overview page shows flows.
- **Suricata** (optional): set `SURICATA_LISTEN=:5514` and forward EVE JSON via syslog.
- **Agents** (optional): enable HTTPS (`TLS_LISTEN_ADDR=:8091`) and install agents from the
  **Agents** page — [tutorial](tutorials/agents.md).

## 5. Turn on enrichment and notifications

Enrichment (geo/rDNS) works out of the box. Add API keys for more:

| Key | Gets you |
|---|---|
| `VT_API_KEY` | VirusTotal IP checks + file reports for agent-reported programs (free tier respected: 4/min, 500/day) |
| `ABUSEIPDB_KEY` | AbuseIPDB confidence scores |
| `GREYNOISE_KEY` | GreyNoise scanner classification |
| `NOTIFY_TELEGRAM_*`, `NOTIFY_NTFY_URL`, … | alert delivery — see [Alerts & notifications](tutorials/alerts.md) |

!!! tip "Next steps"
    - [Deploying & updating](tutorials/deploy.md) — update after `git pull`, migrate an existing database.
    - [Explain](tutorials/explain.md) — the per-program analysis and your own knowledge base.
    - [Configuration reference](reference/configuration.md) — every environment variable.
