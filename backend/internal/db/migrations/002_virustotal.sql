-- VirusTotal reputation data. Separate lookup lifecycle (own quota) from geo/ASN enrichment.
ALTER TABLE ip_info
    ADD COLUMN IF NOT EXISTS vt_malicious     integer,
    ADD COLUMN IF NOT EXISTS vt_suspicious    integer,
    ADD COLUMN IF NOT EXISTS vt_harmless      integer,
    ADD COLUMN IF NOT EXISTS vt_undetected    integer,
    ADD COLUMN IF NOT EXISTS vt_reputation    integer,
    ADD COLUMN IF NOT EXISTS vt_tags          text[],
    ADD COLUMN IF NOT EXISTS vt_network       text,
    ADD COLUMN IF NOT EXISTS vt_last_analysis timestamptz,
    ADD COLUMN IF NOT EXISTS vt_status        text,          -- NULL (never) | ok | failed
    ADD COLUMN IF NOT EXISTS vt_error         text,
    ADD COLUMN IF NOT EXISTS vt_attempts      integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS vt_lookup_at     timestamptz;
CREATE INDEX IF NOT EXISTS ip_info_vt_lookup_idx ON ip_info (vt_lookup_at);
CREATE INDEX IF NOT EXISTS ip_info_vt_malicious_idx ON ip_info (vt_malicious) WHERE vt_malicious > 0;
