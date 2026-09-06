# Troubleshooting

Real problems, in the order you are likely to meet them.

## No flows arriving

- `sudo tcpdump -ni any udp port 2055 -c 5` on the analyzer host: no packets means
  the exporter/firewall side; packets but no data means check `docker compose logs nfacctd`.
- softflowd only exports **expired** flows — generate traffic and wait a minute or two.
- Everything shows as *external*? Add the exporter's WAN address to `LOCAL_NETWORKS`.

## Suricata: "0 events" on the IDS page

- `sudo tcpdump -ni any udp port 5514` — nothing arriving is a pfSense-side setting
  (EVE output type must be **syslog**, and remote logging must include that facility).
- Arriving but not counted: the payload isn't EVE JSON — same fix.
- The IDS page header shows exactly when the listener last received anything.

## pfSense GUI crash: "Allowed memory size … exhausted" in `suricata_logs_browser.php`

pfSense's Suricata **Logs Browser** page can die with a PHP fatal error such as
`Allowed memory size of 536870912 bytes exhausted (tried to allocate 46935402136 bytes)`.
That allocation (~44 GiB) is **larger than the whole disk**, so it is not a real file — the
page computed a bogus read length (an integer/offset bug) and asked PHP for a nonsense buffer.
Confirm your logs are actually fine:

```sh
df -h /                                 # plenty free
ls -lhS /var/log/suricata/suricata_*/   # largest file is small (KB/MB)
```

It is a bug in that GUI page (more likely on a `-CURRENT` / 2.8.1 development snapshot), not a
storage problem. **Just don't open that page** — the analyzer's IDS page already shows every
event over syslog, unaffected by the crash. Report it to Netgate if you want it fixed upstream.
Unrelated but worth doing: keep EVE on **SYSLOG only** so Suricata isn't also writing duplicate
local log files.

## IDS page: "malformed / truncated events (unexpected end of JSON input)"

Not a Suricata or analyzer bug — the UDP **syslog transport** is truncating long EVE lines
(FreeBSD's syslogd caps forwarded messages at ~480 bytes). Long alert records carrying
app-layer metadata are cut off mid-JSON and can't be parsed. Fixes:

1. **Shrink the records**: in Suricata's EVE Output Settings uncheck **"Include App Layer
   metadata"** (under EVE Log Alert details), keep **EVE Log Alert Payload Data Formats = No**,
   and log only Alerts + DNS + TLS. Restart Suricata.
2. **Avoid the UDP limit entirely.** pfSense CE remote logging is **UDP-only** (no TCP option
   on the Settings page), so the bulletproof route is EVE → **file** + a shipper that forwards
   whole lines over **TCP** to `10.0.0.210:5514`. The listener accepts both UDP and TCP and
   reads whole lines over TCP with a 1 MiB buffer, so nothing is truncated. Shrinking the
   records (step 1) is enough for most setups; reach for this only if long DNS/TLS lines persist.

The malformed counter is cumulative since the listener started and only resets when the
analyzer restarts — after the change, watch that it stops climbing rather than expecting the
total to drop. (Any `non-Suricata syslog lines` counted alongside are just other pfSense logs
forwarded to the same port; the analyzer ignores them.)

## `Send test` → `telegram: http 400`

Wrong `NOTIFY_TELEGRAM_CHAT_ID`, or you never sent `/start` to your bot — Telegram bots cannot
message a user first. The analyzer log contains Telegram's error body naming the cause.

## Threat feed errors on the Enrichment page

- `context deadline exceeded` — the feed's server was slow/down; it retries next interval and
  the previous list keeps matching.
- `feed parsed to zero entries; keeping previous list` — the feed changed format or was
  retired (abuse.ch SSLBL was, replaced by ThreatFox in the defaults). Update `THREAT_FEEDS`.

## Windows agent install fails in PowerShell

- *"The underlying connection was closed: An unexpected error occurred on a send"* — you are
  running an **old** installer one-liner that used a script-block certificate callback; Windows
  PowerShell 5.1 cannot run those. Regenerate the command from the current Agents page.
- *"The filename, directory name, or volume label syntax is incorrect"* — you pasted the
  command into `cmd.exe`. Use an administrator **PowerShell**.
- The enrollment token is single-use and valid 24 h — generate a fresh one per install.

## Agent enrolled but no programs / no identity facts

- `pmacct-agent status` on the machine shows enrollment + heartbeat health.
- `sudo pmacct-agent snapshot --seconds 10` shows live attributed connections; if names are
  missing, try `--capture ebpf` (root, cgroup v2, kernel ≥ 5.8).
- Origin/signature rows in Explain need agent ≥ 0.3: `pmacct-agent update` (or wait for
  auto-update after you rebuild the analyzer image).

## The container can't be rebuilt / migrations

- `docker compose up -d --build analyzer` rebuilds only the analyzer; migrations run at start
  and are logged. The database container is never rebuilt and keeps its volume.
- Restoring an old pmacct database: copy its data dir to `deploy/postgres_data/` **while the
  stack is down**; postgres logs should say `Skipping initialization`.
