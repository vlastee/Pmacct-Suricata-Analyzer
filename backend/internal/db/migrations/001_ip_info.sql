-- Enrichment data about external IP addresses, gathered from internet sources.
CREATE TABLE IF NOT EXISTS ip_info (
    ip            inet PRIMARY KEY,
    hostname      text,
    country       text,
    country_code  text,
    region        text,
    city          text,
    lat           double precision,
    lon           double precision,
    timezone      text,
    asn           text,
    as_org        text,
    isp           text,
    org           text,
    is_hosting    boolean,
    is_proxy      boolean,
    is_mobile     boolean,
    source        text,
    status        text NOT NULL DEFAULT 'pending', -- pending | ok | failed
    error         text,
    attempts      integer NOT NULL DEFAULT 0,
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_lookup   timestamptz,
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ip_info_status_idx ON ip_info (status, last_lookup);
CREATE INDEX IF NOT EXISTS ip_info_country_idx ON ip_info (country_code);
CREATE INDEX IF NOT EXISTS ip_info_asn_idx ON ip_info (asn);

-- Speeds up time-window queries over the pmacct accounting table.
CREATE INDEX IF NOT EXISTS acct_stamp_inserted_idx ON acct (stamp_inserted);
CREATE INDEX IF NOT EXISTS acct_ip_src_idx ON acct (ip_src);
CREATE INDEX IF NOT EXISTS acct_ip_dst_idx ON acct (ip_dst);
