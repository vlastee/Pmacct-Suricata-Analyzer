-- User-assigned nicknames for IP addresses (local or external).
CREATE TABLE IF NOT EXISTS ip_nicknames (
    ip         inet PRIMARY KEY,
    nickname   text NOT NULL,
    note       text,
    updated_at timestamptz NOT NULL DEFAULT now()
);
