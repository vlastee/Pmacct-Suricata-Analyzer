-- Endpoint agents: which process on a local machine made which connection.
CREATE TABLE IF NOT EXISTS agents (
    id           bigserial PRIMARY KEY,
    name         text NOT NULL,
    hostname     text NOT NULL DEFAULT '',
    os           text NOT NULL DEFAULT '',
    arch         text NOT NULL DEFAULT '',
    version      text NOT NULL DEFAULT '',
    token_hash   text NOT NULL UNIQUE,          -- sha256 of the bearer token (shown once at enrollment)
    ips          inet[] NOT NULL DEFAULT '{}',
    capture      text NOT NULL DEFAULT '',      -- poll | etw | ebpf
    enrolled_at  timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz,
    last_ip      inet,
    events_total bigint NOT NULL DEFAULT 0,
    last_batch   integer NOT NULL DEFAULT 0,
    dropped      bigint NOT NULL DEFAULT 0,
    revoked_at   timestamptz,
    note         text NOT NULL DEFAULT ''
);

-- Single-use, short-lived tokens created in the UI and exchanged by an agent for its own token.
CREATE TABLE IF NOT EXISTS agent_enroll_tokens (
    token_hash    text PRIMARY KEY,
    name          text NOT NULL DEFAULT '',
    created_by    text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,
    used_by_agent bigint
);

-- Per-minute connection aggregates reported by agents (joins pmacct rows on host/dst/port/minute).
CREATE TABLE IF NOT EXISTS endpoint_conns (
    id        bigserial PRIMARY KEY,
    agent_id  bigint NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    minute    timestamptz NOT NULL,
    host      inet NOT NULL,                    -- local source address
    proto     text NOT NULL,                    -- tcp | udp
    dst       inet NOT NULL,
    dst_port  integer NOT NULL,
    exe       text NOT NULL DEFAULT '',
    name      text NOT NULL DEFAULT '',
    "user"    text NOT NULL DEFAULT '',
    sha256    text NOT NULL DEFAULT '',
    pid       integer NOT NULL DEFAULT 0,
    cmdline   text NOT NULL DEFAULT '',
    count     integer NOT NULL DEFAULT 1,
    bytes     bigint NOT NULL DEFAULT 0,
    UNIQUE (agent_id, minute, host, proto, dst, dst_port, exe, "user")
);
CREATE INDEX IF NOT EXISTS endpoint_conns_host_idx ON endpoint_conns (host, minute DESC);
CREATE INDEX IF NOT EXISTS endpoint_conns_dst_idx ON endpoint_conns (dst, minute DESC);
