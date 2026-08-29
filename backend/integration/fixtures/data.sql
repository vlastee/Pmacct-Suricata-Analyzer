-- Deterministic fixture. Local network for tests: 192.168.1.0/24.
-- Timestamps are relative to now() so the default 24h window always covers them.
-- Totals (all rows): bytes = 100+2000+300+5000+50+40+700+9000+10+30+1234 = 18464 ; flows = 11
-- local -> external (out): 100 + 300 + 50 + 700 + 10 = 1160
-- external -> local (in):  2000 + 5000 + 9000 + 30 = 16030
-- local <-> local:          40 + 1234 = 1274
INSERT INTO acct (ip_src, ip_dst, port_src, port_dst, ip_proto, packets, bytes, stamp_inserted, stamp_updated) VALUES
 ('192.168.1.10', '8.8.8.8',      50000, 53,  17, 1,  100,  date_trunc('minute', now() - interval '10 minutes'), now()),
 ('8.8.8.8',      '192.168.1.10', 53,  50000, 17, 2,  2000, date_trunc('minute', now() - interval '10 minutes'), now()),
 ('192.168.1.10', '1.1.1.1',      50001, 443, 6,  3,  300,  date_trunc('minute', now() - interval '20 minutes'), now()),
 ('1.1.1.1',      '192.168.1.10', 443, 50001, 6,  5,  5000, date_trunc('minute', now() - interval '20 minutes'), now()),
 ('192.168.1.20', '8.8.8.8',      50002, 53,  17, 1,  50,   date_trunc('minute', now() - interval '30 minutes'), now()),
 ('192.168.1.20', '192.168.1.10', 50003, 22,  6,  1,  40,   date_trunc('minute', now() - interval '30 minutes'), now()),
 ('192.168.1.20', '203.0.113.5',  50004, 80,  6,  7,  700,  date_trunc('minute', now() - interval '2 hours'),    now()),
 ('203.0.113.5',  '192.168.1.20', 80,  50004, 6,  9,  9000, date_trunc('minute', now() - interval '2 hours'),    now()),
 ('192.168.1.10', '8.8.8.8',      0,   0,     1,  1,  10,   date_trunc('minute', now() - interval '3 hours'),    now()),
 ('8.8.8.8',      '192.168.1.10', 0,   0,     1,  1,  30,   date_trunc('minute', now() - interval '3 hours'),    now()),
 ('192.168.1.10', '192.168.1.20', 5432, 50005, 6, 12, 1234, date_trunc('minute', now() - interval '4 hours'),    now());
-- One old row outside any 24h window:
INSERT INTO acct (ip_src, ip_dst, port_src, port_dst, ip_proto, packets, bytes, stamp_inserted) VALUES
 ('192.168.1.10', '198.51.100.9', 1, 1, 6, 1, 99999, now() - interval '3 days');
