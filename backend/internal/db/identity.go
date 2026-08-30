package db

import (
	"context"
	"strings"
	"time"
)

// ProgramIdentity is what an agent found out about an executable on the machine itself:
// hashes, the owning package / install channel, whether the file still matches the package
// manifest, and on Windows the Authenticode signature and version resource.
type ProgramIdentity struct {
	AgentID        int64      `json:"agent_id,omitempty"`
	Exe            string     `json:"exe"`
	SHA256         string     `json:"sha256"`
	SHA1           string     `json:"sha1,omitempty"`
	MD5            string     `json:"md5,omitempty"`
	Size           int64      `json:"size"`
	Modified       *time.Time `json:"modified,omitempty"`
	Origin         string     `json:"origin,omitempty"`
	Package        string     `json:"package,omitempty"`
	PackageVersion string     `json:"package_version,omitempty"`
	Verified       *bool      `json:"verified,omitempty"`
	Signature      string     `json:"signature,omitempty"`
	Signer         string     `json:"signer,omitempty"`
	Company        string     `json:"company,omitempty"`
	Product        string     `json:"product,omitempty"`
	FileVersion    string     `json:"file_version,omitempty"`
	Description    string     `json:"description,omitempty"`
	Note           string     `json:"note,omitempty"`
	FirstReported  time.Time  `json:"first_reported"`
	LastReported   time.Time  `json:"last_reported"`
}

// Priority for hash look-ups: files nobody vouches for go first.
func (p *ProgramIdentity) lookupPriority() int {
	switch {
	case p.Verified != nil && !*p.Verified, p.Signature == "invalid":
		return 30
	case p.Origin == "tmp", p.Origin == "download", p.Origin == "unpackaged", p.Signature == "unsigned", p.Signature == "untrusted":
		return 20
	case p.Origin == "home", p.Origin == "opt", p.Origin == "local", p.Origin == "user-install", p.Origin == "venv", p.Origin == "":
		return 10
	}
	return 0
}

// UpsertProgramIdentities stores identity facts for an agent and registers the hashes for the
// file-intelligence lane. Returns the number of rows written.
func (d *DB) UpsertProgramIdentities(ctx context.Context, agentID int64, items []ProgramIdentity) (int, error) {
	n := 0
	for i := range items {
		p := &items[i]
		if p.Exe == "" || len(p.SHA256) != 64 {
			continue
		}
		_, err := d.Pool.Exec(ctx, `
INSERT INTO program_identity (agent_id, exe, sha256, sha1, md5, size, modified, origin, package, package_version, verified,
                              signature, signer, company, product, file_version, description, note)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
ON CONFLICT (agent_id, exe, sha256) DO UPDATE SET
  sha1 = EXCLUDED.sha1, md5 = EXCLUDED.md5, size = EXCLUDED.size, modified = EXCLUDED.modified,
  origin = EXCLUDED.origin, package = EXCLUDED.package, package_version = EXCLUDED.package_version, verified = EXCLUDED.verified,
  signature = EXCLUDED.signature, signer = EXCLUDED.signer, company = EXCLUDED.company, product = EXCLUDED.product,
  file_version = EXCLUDED.file_version, description = EXCLUDED.description, note = EXCLUDED.note, last_reported = now()`,
			agentID, p.Exe, p.SHA256, p.SHA1, p.MD5, p.Size, p.Modified, p.Origin, p.Package, p.PackageVersion, p.Verified,
			p.Signature, p.Signer, p.Company, p.Product, p.FileVersion, p.Description, p.Note)
		if err != nil {
			return n, err
		}
		if _, err := d.Pool.Exec(ctx, `
INSERT INTO file_intel (sha256, sha1, md5, priority) VALUES ($1, $2, $3, $4)
ON CONFLICT (sha256) DO UPDATE SET
  sha1 = CASE WHEN file_intel.sha1 = '' THEN EXCLUDED.sha1 ELSE file_intel.sha1 END,
  md5 = CASE WHEN file_intel.md5 = '' THEN EXCLUDED.md5 ELSE file_intel.md5 END,
  priority = GREATEST(file_intel.priority, EXCLUDED.priority),
  mhr_status = CASE WHEN file_intel.mhr_status = 'skipped' AND EXCLUDED.md5 <> '' THEN 'pending' ELSE file_intel.mhr_status END`,
			p.SHA256, p.SHA1, p.MD5, p.lookupPriority()); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

const identityCols = `agent_id, exe, sha256, sha1, md5, size, modified, origin, package, package_version, verified,
  signature, signer, company, product, file_version, description, note, first_reported, last_reported`

func scanIdentity(row interface{ Scan(...any) error }) (*ProgramIdentity, error) {
	var p ProgramIdentity
	err := row.Scan(&p.AgentID, &p.Exe, &p.SHA256, &p.SHA1, &p.MD5, &p.Size, &p.Modified, &p.Origin, &p.Package, &p.PackageVersion, &p.Verified,
		&p.Signature, &p.Signer, &p.Company, &p.Product, &p.FileVersion, &p.Description, &p.Note, &p.FirstReported, &p.LastReported)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// IdentityFor returns the most recently reported identity of an executable on one agent
// (nil when the agent never described it — an agent older than 0.3, or a process whose file
// could not be read).
func (d *DB) IdentityFor(ctx context.Context, agentID int64, exe string) (*ProgramIdentity, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+identityCols+` FROM program_identity WHERE agent_id = $1 AND exe = $2 ORDER BY last_reported DESC LIMIT 1`, agentID, exe)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanIdentity(rows)
}

// IdentitiesForHash lists what agents reported for one file hash (any machine, any path).
func (d *DB) IdentitiesForHash(ctx context.Context, sha256 string, limit int) ([]ProgramIdentity, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+identityCols+` FROM program_identity WHERE sha256 = $1 ORDER BY last_reported DESC LIMIT $2`, sha256, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProgramIdentity{}
	for rows.Next() {
		p, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// ---- file intelligence (hash look-ups) ----

// FileVT is a VirusTotal file report summary.
type FileVT struct {
	Status       string     `json:"status"` // ok | unknown | failed
	Malicious    *int       `json:"malicious"`
	Suspicious   *int       `json:"suspicious"`
	Harmless     *int       `json:"harmless"`
	Undetected   *int       `json:"undetected"`
	Label        string     `json:"label,omitempty"`
	Names        []string   `json:"names"`
	Signers      []string   `json:"signers"`
	Type         string     `json:"type,omitempty"`
	FirstSeen    *time.Time `json:"first_seen"`
	LastAnalysis *time.Time `json:"last_analysis"`
	Error        *string    `json:"error,omitempty"`
}

// FileMHR is a Team Cymru Malware Hash Registry answer.
type FileMHR struct {
	Status    string     `json:"status"` // listed | clean | failed | skipped
	Detection *int       `json:"detection"`
	LastSeen  *time.Time `json:"last_seen"`
	Error     *string    `json:"error,omitempty"`
}

// FileIntel is everything the hash lanes know about one file.
type FileIntel struct {
	SHA256      string     `json:"sha256"`
	SHA1        string     `json:"sha1,omitempty"`
	MD5         string     `json:"md5,omitempty"`
	Priority    int        `json:"priority"`
	VT          FileVT     `json:"vt"`
	VTLookupAt  *time.Time `json:"vt_lookup_at"`
	VTAttempts  int        `json:"vt_attempts"`
	MHR         FileMHR    `json:"mhr"`
	MHRLookupAt *time.Time `json:"mhr_lookup_at"`
}

const fileIntelCols = `sha256, sha1, md5, priority, vt_status, vt_malicious, vt_suspicious, vt_harmless, vt_undetected, vt_label, vt_names, vt_signers, vt_type,
  vt_first_seen, vt_last_analysis, vt_lookup_at, vt_attempts, vt_error, mhr_status, mhr_detection, mhr_last_seen, mhr_lookup_at, mhr_error`

func scanFileIntel(row interface{ Scan(...any) error }) (*FileIntel, error) {
	var f FileIntel
	err := row.Scan(&f.SHA256, &f.SHA1, &f.MD5, &f.Priority, &f.VT.Status, &f.VT.Malicious, &f.VT.Suspicious, &f.VT.Harmless, &f.VT.Undetected, &f.VT.Label, &f.VT.Names, &f.VT.Signers, &f.VT.Type,
		&f.VT.FirstSeen, &f.VT.LastAnalysis, &f.VTLookupAt, &f.VTAttempts, &f.VT.Error, &f.MHR.Status, &f.MHR.Detection, &f.MHR.LastSeen, &f.MHRLookupAt, &f.MHR.Error)
	if err != nil {
		return nil, err
	}
	if f.VT.Names == nil {
		f.VT.Names = []string{}
	}
	if f.VT.Signers == nil {
		f.VT.Signers = []string{}
	}
	return &f, nil
}

// FileIntelFor returns the record for a hash, or nil.
func (d *DB) FileIntelFor(ctx context.Context, sha256 string) (*FileIntel, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+fileIntelCols+` FROM file_intel WHERE sha256 = $1`, strings.ToLower(sha256))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanFileIntel(rows)
}

// FileVTCandidates picks hashes for VirusTotal: never looked up first (highest priority
// first), then reports older than refreshAfter, then failures after exponential backoff.
func (d *DB) FileVTCandidates(ctx context.Context, refreshAfter time.Duration, limit int) ([]string, error) {
	rows, err := d.Pool.Query(ctx, `
SELECT sha256 FROM file_intel
WHERE vt_lookup_at IS NULL
   OR (vt_status IN ('ok', 'unknown') AND vt_lookup_at < now() - $1::interval)
   OR (vt_status = 'failed' AND vt_lookup_at < now() - (interval '30 minutes' * power(2, LEAST(vt_attempts, 6))))
ORDER BY (vt_lookup_at IS NULL) DESC, priority DESC, created_at
LIMIT $2`, refreshAfter.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// FileMHRCandidates picks hashes for the Malware Hash Registry (needs an MD5 or SHA-1).
func (d *DB) FileMHRCandidates(ctx context.Context, refreshAfter time.Duration, limit int) ([]FileIntel, error) {
	rows, err := d.Pool.Query(ctx, `
SELECT sha256, sha1, md5 FROM file_intel
WHERE (md5 <> '' OR sha1 <> '')
  AND (mhr_lookup_at IS NULL
       OR (mhr_status IN ('listed', 'clean') AND mhr_lookup_at < now() - $1::interval)
       OR (mhr_status = 'failed' AND mhr_lookup_at < now() - interval '2 hours'))
ORDER BY (mhr_lookup_at IS NULL) DESC, priority DESC, created_at
LIMIT $2`, refreshAfter.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FileIntel
	for rows.Next() {
		var f FileIntel
		if err := rows.Scan(&f.SHA256, &f.SHA1, &f.MD5); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// UpsertFileVT stores a VirusTotal file result.
func (d *DB) UpsertFileVT(ctx context.Context, sha256 string, v *FileVT) error {
	names, signers := v.Names, v.Signers
	if names == nil {
		names = []string{}
	}
	if signers == nil {
		signers = []string{}
	}
	_, err := d.Pool.Exec(ctx, `
INSERT INTO file_intel (sha256, vt_status, vt_malicious, vt_suspicious, vt_harmless, vt_undetected, vt_label, vt_names, vt_signers, vt_type,
                        vt_first_seen, vt_last_analysis, vt_error, vt_attempts, vt_lookup_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 1, now())
ON CONFLICT (sha256) DO UPDATE SET
  vt_status = EXCLUDED.vt_status,
  vt_malicious = COALESCE(EXCLUDED.vt_malicious, file_intel.vt_malicious),
  vt_suspicious = COALESCE(EXCLUDED.vt_suspicious, file_intel.vt_suspicious),
  vt_harmless = COALESCE(EXCLUDED.vt_harmless, file_intel.vt_harmless),
  vt_undetected = COALESCE(EXCLUDED.vt_undetected, file_intel.vt_undetected),
  vt_label = CASE WHEN EXCLUDED.vt_status = 'ok' THEN EXCLUDED.vt_label ELSE file_intel.vt_label END,
  vt_names = CASE WHEN EXCLUDED.vt_status = 'ok' THEN EXCLUDED.vt_names ELSE file_intel.vt_names END,
  vt_signers = CASE WHEN EXCLUDED.vt_status = 'ok' THEN EXCLUDED.vt_signers ELSE file_intel.vt_signers END,
  vt_type = CASE WHEN EXCLUDED.vt_status = 'ok' THEN EXCLUDED.vt_type ELSE file_intel.vt_type END,
  vt_first_seen = COALESCE(EXCLUDED.vt_first_seen, file_intel.vt_first_seen),
  vt_last_analysis = COALESCE(EXCLUDED.vt_last_analysis, file_intel.vt_last_analysis),
  vt_error = EXCLUDED.vt_error, vt_attempts = file_intel.vt_attempts + 1, vt_lookup_at = now(), updated_at = now()`,
		strings.ToLower(sha256), v.Status, v.Malicious, v.Suspicious, v.Harmless, v.Undetected, v.Label, names, signers, v.Type, v.FirstSeen, v.LastAnalysis, v.Error)
	return err
}

// UpsertFileMHR stores a Malware Hash Registry answer.
func (d *DB) UpsertFileMHR(ctx context.Context, sha256 string, m *FileMHR) error {
	_, err := d.Pool.Exec(ctx, `
INSERT INTO file_intel (sha256, mhr_status, mhr_detection, mhr_last_seen, mhr_error, mhr_lookup_at) VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (sha256) DO UPDATE SET mhr_status = EXCLUDED.mhr_status, mhr_detection = EXCLUDED.mhr_detection,
  mhr_last_seen = EXCLUDED.mhr_last_seen, mhr_error = EXCLUDED.mhr_error, mhr_lookup_at = now(), updated_at = now()`,
		strings.ToLower(sha256), m.Status, m.Detection, m.LastSeen, m.Error)
	return err
}

// FileIntelStats summarises the hash lanes for the enrichment page.
type FileIntelStats struct {
	Files       int64 `json:"files"`
	VTPending   int64 `json:"vt_pending"`
	VTChecked   int64 `json:"vt_checked"`
	VTUnknown   int64 `json:"vt_unknown"`
	VTFlagged   int64 `json:"vt_flagged"`
	MHRChecked  int64 `json:"mhr_checked"`
	MHRListed   int64 `json:"mhr_listed"`
	Identities  int64 `json:"identities"`
	LOLBinsRows int64 `json:"lolbins"`
}

// FileIntelSummary counts files by state.
func (d *DB) FileIntelSummary(ctx context.Context) (*FileIntelStats, error) {
	var s FileIntelStats
	err := d.Pool.QueryRow(ctx, `SELECT
  (SELECT COUNT(*) FROM file_intel),
  (SELECT COUNT(*) FROM file_intel WHERE vt_status = 'pending'),
  (SELECT COUNT(*) FROM file_intel WHERE vt_status IN ('ok', 'unknown')),
  (SELECT COUNT(*) FROM file_intel WHERE vt_status = 'unknown'),
  (SELECT COUNT(*) FROM file_intel WHERE vt_status = 'ok' AND COALESCE(vt_malicious, 0) > 0),
  (SELECT COUNT(*) FROM file_intel WHERE mhr_status IN ('listed', 'clean')),
  (SELECT COUNT(*) FROM file_intel WHERE mhr_status = 'listed'),
  (SELECT COUNT(*) FROM program_identity),
  (SELECT COUNT(*) FROM lolbins)`).Scan(&s.Files, &s.VTPending, &s.VTChecked, &s.VTUnknown, &s.VTFlagged, &s.MHRChecked, &s.MHRListed, &s.Identities, &s.LOLBinsRows)
	return &s, err
}

// ---- LOLBAS / GTFOBins ----

// LOLBin is a catalogue entry for a legitimate system binary that attackers abuse.
type LOLBin struct {
	Source      string   `json:"source"` // lolbas | gtfobins
	Name        string   `json:"name"`
	Display     string   `json:"display"`
	Description string   `json:"description"`
	Functions   []string `json:"functions"`
	Paths       []string `json:"paths"`
	Mitre       []string `json:"mitre"`
	URL         string   `json:"url"`
}

// LOLBinName normalises an executable name for catalogue matching.
func LOLBinName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndexAny(n, `/\`); i >= 0 {
		n = n[i+1:]
	}
	return strings.TrimSuffix(n, ".exe")
}

// ReplaceLOLBins swaps one source's catalogue atomically.
func (d *DB) ReplaceLOLBins(ctx context.Context, source string, items []LOLBin) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM lolbins WHERE source = $1`, source); err != nil {
		return err
	}
	for _, it := range items {
		name := LOLBinName(it.Name)
		if name == "" {
			continue
		}
		for _, p := range []*[]string{&it.Functions, &it.Paths, &it.Mitre} {
			if *p == nil {
				*p = []string{}
			}
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO lolbins (source, name, display, description, functions, paths, mitre, url, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
ON CONFLICT (source, name) DO UPDATE SET display = EXCLUDED.display, description = EXCLUDED.description, functions = EXCLUDED.functions,
  paths = EXCLUDED.paths, mitre = EXCLUDED.mitre, url = EXCLUDED.url, updated_at = now()`,
			source, name, it.Display, it.Description, it.Functions, it.Paths, it.Mitre, it.URL); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// LOLBinFor finds a catalogue entry by program name; os narrows the source ("windows" →
// LOLBAS, "linux" → GTFOBins, "" → either).
func (d *DB) LOLBinFor(ctx context.Context, name, os string) (*LOLBin, error) {
	n := LOLBinName(name)
	if n == "" {
		return nil, nil
	}
	sources := []string{"lolbas", "gtfobins"}
	switch strings.ToLower(os) {
	case "windows":
		sources = []string{"lolbas"}
	case "linux", "darwin", "freebsd":
		sources = []string{"gtfobins"}
	}
	rows, err := d.Pool.Query(ctx, `SELECT source, name, display, description, functions, paths, mitre, url FROM lolbins WHERE name = $1 AND source = ANY($2) ORDER BY source LIMIT 1`, n, sources)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	var l LOLBin
	if err := rows.Scan(&l.Source, &l.Name, &l.Display, &l.Description, &l.Functions, &l.Paths, &l.Mitre, &l.URL); err != nil {
		return nil, err
	}
	return &l, nil
}

// LOLBinCounts returns rows per source.
func (d *DB) LOLBinCounts(ctx context.Context) (map[string]int, error) {
	rows, err := d.Pool.Query(ctx, `SELECT source, COUNT(*) FROM lolbins GROUP BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}
