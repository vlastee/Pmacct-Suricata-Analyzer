# Deploying & updating

## Layout

The compose file in [`deploy/`](https://github.com/vlastee/Pmacct-Suricata-Analyzer/tree/master/deploy)
runs three services:

| Service | Role | Data |
|---|---|---|
| `postgres` | flow + analyzer storage | `deploy/postgres_data/` |
| `nfacctd` | pmacct NetFlow collector, writes into PostgreSQL | — |
| `analyzer` | Go API + UI + agent downloads, built from the repo's `Containerfile` | state lives in the DB |

## Updating after `git pull`

The analyzer image contains the backend, the built frontend **and** the agent binaries, so an
update is: pull, rebuild, restart. Database migrations apply automatically at startup.

```bash
cd Pmacct-Suricata-Analyzer
git pull
cd deploy
docker compose up -d --build analyzer   # only the analyzer needs rebuilding
docker compose logs -f analyzer         # watch the migrations apply
```

- `postgres` and `nfacctd` keep running; your data is untouched.
- If the **agent** version was bumped, enrolled agents self-update on their next heartbeat
  (staggered), as long as auto-update is enabled — see [Endpoint agents](tutorials/../agents.md).
- Rollback: `git checkout <old-commit> && docker compose up -d --build analyzer`. Migrations
  are additive, so an older binary runs fine against a newer schema in almost all cases.

## Deploying without a git checkout

If the repo is private and the server has no deploy key, `rsync` works just as well:

```bash
rsync -a --delete --exclude .git --exclude deploy/postgres_data \
    ./Pmacct-Suricata-Analyzer/ server:/opt/Pmacct-Suricata-Analyzer/
ssh server 'cd /opt/Pmacct-Suricata-Analyzer/deploy && docker compose up -d --build analyzer'
```

## Migrating an existing pmacct database

Already have a pmacct/Grafana stack with data? Stop it, copy its PostgreSQL data directory into
`deploy/postgres_data/`, and start the stack — the analyzer's migrations add its own tables next
to the existing `acct` table:

```bash
docker compose down
sudo cp -a /path/to/old/postgres_data deploy/postgres_data
docker compose up -d
# postgres logs will say: "Skipping initialization" — the old data is used as-is
```

## Health

- `GET /healthz` returns `{"status":"ok"}` and backs the container's HEALTHCHECK.
- `docker compose ps` shows health; the **Enrichment** page shows lane/feed status;
  the **IDS** page shows the Suricata listener.
