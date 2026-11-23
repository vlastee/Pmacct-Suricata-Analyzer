-- pfSense firewall log (filterlog) records received over syslog. One row per logged packet;
-- kept FIREWALL_RETENTION_DAYS (default 30) by the daily prune.
CREATE TABLE IF NOT EXISTS fw_events (
    ts          timestamptz NOT NULL,
    action      text NOT NULL,      -- pass | block | reject
    direction   text,               -- in | out
    iface       text,               -- real interface (vtnet0, igb1, …)
    reason      text,               -- usually "match"
    rule_num    integer,
    sub_rule    text,
    anchor      text,
    tracker     bigint,             -- stable rule id (user rules: creation timestamp)
    ip_version  smallint,
    proto       smallint,           -- IP protocol number
    proto_name  text,               -- tcp | udp | icmp | …
    src_ip      inet,
    src_port    integer,
    dst_ip      inet,
    dst_port    integer,
    length      integer,
    ttl         smallint,
    tcp_flags   text,
    icmp_type   text
);
CREATE INDEX IF NOT EXISTS fw_events_ts_idx ON fw_events USING brin (ts);
CREATE INDEX IF NOT EXISTS fw_events_src_idx ON fw_events (src_ip, ts DESC);
CREATE INDEX IF NOT EXISTS fw_events_dst_idx ON fw_events (dst_ip, ts DESC);
