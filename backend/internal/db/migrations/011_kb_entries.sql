-- User-maintained knowledge base for Explain: matched by program name (glob), executable path
-- (glob) or SHA-256; takes precedence over the built-in entries.
CREATE TABLE IF NOT EXISTS kb_entries (
    id          bigserial PRIMARY KEY,
    match_kind  text NOT NULL CHECK (match_kind IN ('name', 'path', 'hash')),
    pattern     text NOT NULL,
    title       text NOT NULL,
    category    text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    expected    text NOT NULL DEFAULT '',
    verify      text[] NOT NULL DEFAULT '{}',
    risk        text NOT NULL DEFAULT '',
    note        text NOT NULL DEFAULT '',
    created_by  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (match_kind, pattern)
);
