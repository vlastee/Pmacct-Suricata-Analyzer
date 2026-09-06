# Adding screenshots

The images under `docs/images/` are generated placeholders until real screenshots replace
them. Take them from a browser window about **1600×900**, in whichever theme you prefer (the
site shows them as-is in both), save as PNG over the placeholder file, commit, push — the site
rebuilds itself.

| File | What to capture |
|---|---|
| `images/overview.png` | **Overview** page with a day of traffic: totals, timeline, top talkers, threats |
| `images/host-detail.png` | A LAN host's page showing peers, the **Programs** card (agent data), notes and a trust button |
| `images/ids.png` | **IDS** page with the listener status and a few Suricata events |
| `images/alerts.png` | **Alerts** page with open + resolved alerts of mixed severity |
| `images/rules.png` | **Rules** page: rule list with a custom rule, the trusted list and the knowledge-base card |
| `images/enrichment.png` | **Enrichment** page: lanes with quotas, threat feeds, the files lane, notifications |
| `images/agents.png` | **Agents** page: the installer builder with a generated one-liner (redact the token) and the agent list |
| `images/agent-activity.png` | An agent expanded: per-program activity, destinations, timeline |
| `images/explain.png` | An **Explain** panel for an interesting program — ideally one with identity facts (Origin/Signature rows) and a VirusTotal/MHR verdict |

!!! warning "Before you commit a screenshot"
    Redact anything sensitive: enrollment tokens, public IPs you don't want published,
    real hostnames/nicknames. The installer one-liner in particular contains a live token.
