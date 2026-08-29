-- User-defined detection rules (see backend/internal/rules/custom.go). Built-in rules keep their
-- overrides in settings["rules"]; a custom rule is entirely described by its row here.
CREATE TABLE IF NOT EXISTS custom_rules (
    name         text PRIMARY KEY,
    title        text NOT NULL,
    description  text NOT NULL DEFAULT '',
    kind         text NOT NULL CHECK (kind IN ('sql', 'builtin')),
    base         text NOT NULL DEFAULT '',          -- kind=builtin: built-in rule whose detector is reused
    sql          text NOT NULL DEFAULT '',          -- kind=sql: SELECT returning host, peer, port, title, severity, details, key
    params       jsonb NOT NULL DEFAULT '{}'::jsonb,
    severity     text NOT NULL DEFAULT 'warning',
    interval_s   integer NOT NULL DEFAULT 60,
    window_s     integer NOT NULL DEFAULT 600,
    enabled      boolean NOT NULL DEFAULT true,
    exempt_hosts text[] NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- Resolved alerts can be reopened; auto-resolve then keys off the later of last_seen / reopened_at.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS reopened_at timestamptz;
