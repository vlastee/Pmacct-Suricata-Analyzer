# HTTP API

The UI is a thin client — everything it shows comes from `GET/POST` JSON endpoints under
`/api/v1/`, authenticated by session cookie (agents use their own bearer tokens). The full
route list is kept in the
[README](https://github.com/vlastee/Pmacct-Suricata-Analyzer/blob/master/README.md#http-api);
the families:

| Area | Endpoints (examples) |
|---|---|
| Traffic | `/api/v1/overview`, `/api/v1/hosts`, `/api/v1/hosts/{ip}`, `/api/v1/flows` |
| Enrichment | `/api/v1/ips/{ip}`, `/api/v1/enrichment/status`, `/api/v1/system/status` |
| Alerts & rules | `/api/v1/alerts…`, `/api/v1/rules…`, `/api/v1/rules/custom…`, `/api/v1/exclusions`, `/api/v1/notes` |
| Knowledge base | `/api/v1/kb`, `/api/v1/kb/import`, `/api/v1/kb?export=1` |
| Explain | `/api/v1/explain/program?agent=…\|host=…&exe=…&user=…&container=…&since=…` |
| Agents (admin) | `/api/v1/agents…`, `/api/v1/agents/enroll-tokens`, `/api/v1/agents/{id}/activity`, `/api/v1/agents/settings` |
| Agent protocol | `POST /api/v1/agent/enroll`, `POST /api/v1/agent/events` (bearer, gzip JSON), `/api/v1/agent/builds`, `/api/v1/agent/download/{target}`, `/api/v1/agent/install.sh|.ps1` |
| TLS | `/api/v1/tls/info` (CA fingerprint + SPKI pin), `/api/v1/tls/ca` |
| Health | `/healthz` |

All timestamps are UTC; window parameters accept `since=1h|24h|7d…` style durations.

Example — explain a program seen by agent 3:

```bash
curl -s --cacert ca.pem -b "$SESSION" \
  'https://10.0.0.210:8091/api/v1/explain/program?agent=3&exe=/usr/bin/curl&user=petro&since=24h' | jq .assessment
```
