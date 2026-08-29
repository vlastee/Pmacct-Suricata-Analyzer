-- Global "trusted" addresses: findings from every rule (and Suricata) are dropped when the host
-- or the peer matches. Patterns are an IP, a CIDR, or a hostname glob ("*.anthropic.com").
CREATE TABLE IF NOT EXISTS alert_exclusions (
    id         bigserial PRIMARY KEY,
    pattern    text NOT NULL UNIQUE,
    kind       text NOT NULL CHECK (kind IN ('ip', 'cidr', 'name')),
    note       text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
