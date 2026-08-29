-- Alerting backbone, rollups for baselines, threat lists, IDS events, names, device kinds, reputation lanes.

-- Key/value settings (rule configuration, job cursors).
CREATE TABLE IF NOT EXISTS settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Alerts produced by the rules engine and by IDS ingest. One open row per dedupe_key.
CREATE TABLE IF NOT EXISTS alerts (
    id          bigserial PRIMARY KEY,
    rule        text NOT NULL,
    severity    text NOT NULL,                 -- info | warning | critical
    host        inet,                          -- local host involved (if any)
    peer        inet,                          -- remote side (if any)
    port        integer,
    title       text NOT NULL,
    details     jsonb NOT NULL DEFAULT '{}',
    count       integer NOT NULL DEFAULT 1,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    state       text NOT NULL DEFAULT 'open',  -- open | acked | resolved
    acked_at    timestamptz,
    resolved_at timestamptz,
    notified_at timestamptz,
    dedupe_key  text NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS alerts_open_dedupe_idx ON alerts (dedupe_key) WHERE state <> 'resolved';
CREATE INDEX IF NOT EXISTS alerts_state_idx ON alerts (state, last_seen DESC);
CREATE INDEX IF NOT EXISTS alerts_host_idx ON alerts (host, last_seen DESC);
CREATE INDEX IF NOT EXISTS alerts_peer_idx ON alerts (peer, last_seen DESC);

-- Hourly per-host rollups (survive the 7-day raw retention; used for baselines).
CREATE TABLE IF NOT EXISTS host_hourly (
    host      inet NOT NULL,
    hour      timestamptz NOT NULL,
    bytes_in  bigint NOT NULL DEFAULT 0,
    bytes_out bigint NOT NULL DEFAULT 0,
    packets   bigint NOT NULL DEFAULT 0,
    flows     bigint NOT NULL DEFAULT 0,
    peers     integer NOT NULL DEFAULT 0,
    ports     integer NOT NULL DEFAULT 0,
    PRIMARY KEY (host, hour)
);
CREATE INDEX IF NOT EXISTS host_hourly_hour_idx ON host_hourly (hour);

-- Daily per-host/peer history (for "new destination" detection).
CREATE TABLE IF NOT EXISTS host_peer_daily (
    host  inet NOT NULL,
    peer  inet NOT NULL,
    day   date NOT NULL,
    bytes bigint NOT NULL DEFAULT 0,
    flows bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (host, peer, day)
);
CREATE INDEX IF NOT EXISTS host_peer_daily_peer_idx ON host_peer_daily (peer);

-- Threat intelligence lists (bulk feeds), matched locally.
CREATE TABLE IF NOT EXISTS threat_lists (
    net      cidr NOT NULL,
    list     text NOT NULL,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (net, list)
);
CREATE INDEX IF NOT EXISTS threat_lists_net_gist ON threat_lists USING gist (net inet_ops);

-- Suricata EVE alerts.
CREATE TABLE IF NOT EXISTS ids_events (
    id         bigserial PRIMARY KEY,
    ts         timestamptz NOT NULL,
    src_ip     inet,
    src_port   integer,
    dst_ip     inet,
    dst_port   integer,
    proto      text,
    sid        bigint,
    signature  text,
    category   text,
    severity   integer,
    action     text,
    app_proto  text,
    raw        jsonb
);
CREATE INDEX IF NOT EXISTS ids_events_ts_idx ON ids_events (ts DESC);
CREATE INDEX IF NOT EXISTS ids_events_src_idx ON ids_events (src_ip, ts DESC);
CREATE INDEX IF NOT EXISTS ids_events_dst_idx ON ids_events (dst_ip, ts DESC);

-- Names observed for IPs (Suricata DNS answers, TLS SNI, HTTP Host, reverse DNS).
CREATE TABLE IF NOT EXISTS ip_names (
    ip         inet NOT NULL,
    name       text NOT NULL,
    source     text NOT NULL,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    hits       integer NOT NULL DEFAULT 1,
    PRIMARY KEY (ip, name)
);

-- Device kind on nicknames (pc | phone | server | iot | network | other).
ALTER TABLE ip_nicknames ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'other';

-- Additional reputation sources (AbuseIPDB, GreyNoise), one row per (ip, source).
CREATE TABLE IF NOT EXISTS ip_reputation (
    ip        inet NOT NULL,
    source    text NOT NULL,
    status    text NOT NULL,            -- ok | failed
    error     text,
    attempts  integer NOT NULL DEFAULT 0,
    lookup_at timestamptz NOT NULL DEFAULT now(),
    score     integer,                  -- source-specific 0-100 badness score
    flagged   boolean NOT NULL DEFAULT false,
    data      jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (ip, source)
);
CREATE INDEX IF NOT EXISTS ip_reputation_flagged_idx ON ip_reputation (source) WHERE flagged;
