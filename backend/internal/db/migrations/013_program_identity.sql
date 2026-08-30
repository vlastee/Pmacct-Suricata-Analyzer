-- Program identity facts reported by agents (once per executable + hash), file intelligence
-- keyed by hash (VirusTotal file reports, Team Cymru Malware Hash Registry), and the
-- LOLBAS / GTFOBins catalogues of abusable system binaries.

CREATE TABLE IF NOT EXISTS program_identity (
  agent_id        bigint NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  exe             text NOT NULL,
  sha256          text NOT NULL,
  sha1            text NOT NULL DEFAULT '',
  md5             text NOT NULL DEFAULT '',
  size            bigint NOT NULL DEFAULT 0,
  modified        timestamptz,
  origin          text NOT NULL DEFAULT '',   -- dpkg | apk | pacman | snap | flatpak | ... | windows | program-files | ...
  package         text NOT NULL DEFAULT '',
  package_version text NOT NULL DEFAULT '',
  verified        boolean,                    -- file matches the package manifest (NULL = no manifest)
  signature       text NOT NULL DEFAULT '',   -- Windows: valid | unsigned | untrusted | invalid
  signer          text NOT NULL DEFAULT '',
  company         text NOT NULL DEFAULT '',
  product         text NOT NULL DEFAULT '',
  file_version    text NOT NULL DEFAULT '',
  description     text NOT NULL DEFAULT '',
  note            text NOT NULL DEFAULT '',
  first_reported  timestamptz NOT NULL DEFAULT now(),
  last_reported   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (agent_id, exe, sha256)
);
CREATE INDEX IF NOT EXISTS program_identity_sha256 ON program_identity (sha256);

CREATE TABLE IF NOT EXISTS file_intel (
  sha256           text PRIMARY KEY,
  sha1             text NOT NULL DEFAULT '',
  md5              text NOT NULL DEFAULT '',
  priority         int NOT NULL DEFAULT 0,          -- unsigned / unpackaged files are looked up first
  vt_status        text NOT NULL DEFAULT 'pending', -- pending | ok | unknown (never submitted) | failed
  vt_malicious     int,
  vt_suspicious    int,
  vt_harmless      int,
  vt_undetected    int,
  vt_label         text NOT NULL DEFAULT '',        -- suggested threat label
  vt_names         text[] NOT NULL DEFAULT '{}',
  vt_signers       text[] NOT NULL DEFAULT '{}',
  vt_type          text NOT NULL DEFAULT '',
  vt_first_seen    timestamptz,
  vt_last_analysis timestamptz,
  vt_lookup_at     timestamptz,
  vt_attempts      int NOT NULL DEFAULT 0,
  vt_error         text,
  mhr_status       text NOT NULL DEFAULT 'pending', -- pending | listed | clean | failed | skipped (no md5)
  mhr_detection    int,                             -- AV detection percentage reported by Cymru
  mhr_last_seen    timestamptz,
  mhr_lookup_at    timestamptz,
  mhr_error        text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS file_intel_vt_pending ON file_intel (priority DESC, created_at) WHERE vt_status = 'pending';

CREATE TABLE IF NOT EXISTS lolbins (
  source      text NOT NULL,                 -- lolbas | gtfobins
  name        text NOT NULL,                 -- lower-case executable name without .exe
  display     text NOT NULL DEFAULT '',
  description text NOT NULL DEFAULT '',
  functions   text[] NOT NULL DEFAULT '{}',  -- what it can be abused for
  paths       text[] NOT NULL DEFAULT '{}',
  mitre       text[] NOT NULL DEFAULT '{}',
  url         text NOT NULL DEFAULT '',
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source, name)
);
