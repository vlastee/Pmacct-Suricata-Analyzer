-- Minimal replica of the pmacct PostgreSQL schema (pmacct's pgsql v1 "acct" table + proto lookup).
CREATE TABLE IF NOT EXISTS acct (
    mac_src        macaddr NOT NULL DEFAULT '00:00:00:00:00:00',
    mac_dst        macaddr NOT NULL DEFAULT '00:00:00:00:00:00',
    ip_src         inet NOT NULL DEFAULT '0.0.0.0',
    ip_dst         inet NOT NULL DEFAULT '0.0.0.0',
    port_src       integer NOT NULL DEFAULT 0,
    port_dst       integer NOT NULL DEFAULT 0,
    ip_proto       smallint NOT NULL DEFAULT 0,
    packets        integer NOT NULL,
    bytes          bigint NOT NULL,
    stamp_inserted timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    stamp_updated  timestamp without time zone,
    CONSTRAINT acct_pk PRIMARY KEY (mac_src, mac_dst, ip_src, ip_dst, port_src, port_dst, ip_proto, stamp_inserted)
);
CREATE TABLE IF NOT EXISTS proto (num smallint, description char(20));
INSERT INTO proto VALUES (1,'icmp'),(6,'tcp'),(17,'udp');
