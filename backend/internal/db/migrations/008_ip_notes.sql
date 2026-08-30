-- Free-form notes per address (a journal: many timestamped entries, with the author).
CREATE TABLE IF NOT EXISTS ip_notes (
    id         bigserial PRIMARY KEY,
    ip         inet NOT NULL,
    body       text NOT NULL,
    author     text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ip_notes_ip_idx ON ip_notes (ip, created_at DESC);
