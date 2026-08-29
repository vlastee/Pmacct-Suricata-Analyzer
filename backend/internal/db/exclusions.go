package db

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Exclusion is one "trusted" pattern: alerts whose host or peer matches are never raised.
type Exclusion struct {
	ID        int64     `json:"id"`
	Pattern   string    `json:"pattern"`
	Kind      string    `json:"kind"` // ip | cidr | name
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

var namePatternRe = regexp.MustCompile(`^[a-z0-9*][a-z0-9*._-]*$`)

// NormalizeExclusion canonicalises user input: an address ("10.0.0.5", "::ffff:1.2.3.4"),
// a network ("203.0.113.0/24", masked), or a case-insensitive hostname glob ("*.anthropic.com",
// "discord.com") matched against rDNS hostnames and DNS/TLS-learned names.
func NormalizeExclusion(pattern string) (norm, kind string, err error) {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return "", "", errors.New("pattern is empty")
	}
	if a, err := netip.ParseAddr(p); err == nil {
		return a.Unmap().String(), "ip", nil
	}
	if pf, err := netip.ParsePrefix(p); err == nil {
		pf = netip.PrefixFrom(pf.Addr().Unmap(), pf.Bits()).Masked()
		if pf.IsSingleIP() {
			return pf.Addr().String(), "ip", nil
		}
		return pf.String(), "cidr", nil
	}
	p = strings.ToLower(strings.TrimSuffix(p, "."))
	if !namePatternRe.MatchString(p) || strings.Trim(p, "*.") == "" {
		return "", "", errors.New("pattern must be an IP, a CIDR, or a hostname (wildcards allowed, e.g. *.example.com)")
	}
	return p, "name", nil
}

// ListExclusions returns all patterns, oldest first.
func (d *DB) ListExclusions(ctx context.Context) ([]Exclusion, error) {
	rows, err := d.Pool.Query(ctx, `SELECT id, pattern, kind, note, created_at FROM alert_exclusions ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Exclusion{}
	for rows.Next() {
		var e Exclusion
		if err := rows.Scan(&e.ID, &e.Pattern, &e.Kind, &e.Note, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddExclusion stores a pattern (updating the note if it already exists).
func (d *DB) AddExclusion(ctx context.Context, pattern, note string) (*Exclusion, error) {
	norm, kind, err := NormalizeExclusion(pattern)
	if err != nil {
		return nil, err
	}
	var e Exclusion
	err = d.Pool.QueryRow(ctx, `INSERT INTO alert_exclusions (pattern, kind, note) VALUES ($1, $2, $3)
ON CONFLICT (pattern) DO UPDATE SET note = EXCLUDED.note
RETURNING id, pattern, kind, note, created_at`, norm, kind, strings.TrimSpace(note)).Scan(&e.ID, &e.Pattern, &e.Kind, &e.Note, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// DeleteExclusion removes one pattern by id.
func (d *DB) DeleteExclusion(ctx context.Context, id int64) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM alert_exclusions WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ExclusionSet matches addresses (and the names known for them) against the patterns.
type ExclusionSet struct {
	ips   map[string]string
	cidrs []cidrPattern
	names []namePattern
}

type cidrPattern struct {
	prefix  netip.Prefix
	pattern string
}

type namePattern struct {
	re      *regexp.Regexp
	pattern string
}

// NewExclusionSet compiles a list of patterns.
func NewExclusionSet(list []Exclusion) *ExclusionSet {
	s := &ExclusionSet{ips: map[string]string{}}
	for _, e := range list {
		switch e.Kind {
		case "ip":
			s.ips[e.Pattern] = e.Pattern
		case "cidr":
			if pf, err := netip.ParsePrefix(e.Pattern); err == nil {
				s.cidrs = append(s.cidrs, cidrPattern{pf, e.Pattern})
			}
		case "name":
			re := "^" + strings.ReplaceAll(regexp.QuoteMeta(e.Pattern), `\*`, ".*") + "$"
			if r, err := regexp.Compile(re); err == nil {
				s.names = append(s.names, namePattern{r, e.Pattern})
			}
		}
	}
	return s
}

// Empty reports whether nothing can ever match.
func (s *ExclusionSet) Empty() bool {
	return s == nil || (len(s.ips) == 0 && len(s.cidrs) == 0 && len(s.names) == 0)
}

// HasNames reports whether name lookups are needed to evaluate the set.
func (s *ExclusionSet) HasNames() bool { return s != nil && len(s.names) > 0 }

// MatchIP returns the pattern covering ip, if any.
func (s *ExclusionSet) MatchIP(ip string) (string, bool) {
	if s == nil || ip == "" {
		return "", false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	if p, ok := s.ips[a.String()]; ok {
		return p, true
	}
	for _, c := range s.cidrs {
		if c.prefix.Contains(a) {
			return c.pattern, true
		}
	}
	return "", false
}

// Match checks the address and then every name known for it.
func (s *ExclusionSet) Match(ip string, names []string) (string, bool) {
	if p, ok := s.MatchIP(ip); ok {
		return p, true
	}
	if s == nil || len(s.names) == 0 {
		return "", false
	}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" {
			continue
		}
		for _, np := range s.names {
			if np.re.MatchString(n) {
				return np.pattern, true
			}
		}
	}
	return "", false
}

// LoadExclusions reads and compiles the current list.
func (d *DB) LoadExclusions(ctx context.Context) (*ExclusionSet, error) {
	list, err := d.ListExclusions(ctx)
	if err != nil {
		return nil, err
	}
	return NewExclusionSet(list), nil
}

// NamesForIPs returns every name known for each address: the enrichment rDNS hostname plus
// DNS/TLS/HTTP-learned names.
func (d *DB) NamesForIPs(ctx context.Context, ips []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(ips) == 0 {
		return out, nil
	}
	rows, err := d.Pool.Query(ctx, `
SELECT host(ip), name FROM ip_names WHERE ip = ANY($1::inet[])
UNION
SELECT host(ip), hostname FROM ip_info WHERE ip = ANY($1::inet[]) AND hostname IS NOT NULL AND hostname <> ''`, ips)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip, name string
		if err := rows.Scan(&ip, &name); err != nil {
			return nil, err
		}
		out[ip] = append(out[ip], name)
	}
	return out, rows.Err()
}

// ResolveExcludedAlerts resolves every open/acked alert whose host or peer the set covers and
// returns how many it closed — used when a pattern is added, so the list clears immediately.
func (d *DB) ResolveExcludedAlerts(ctx context.Context, set *ExclusionSet) (int64, error) {
	if set.Empty() {
		return 0, nil
	}
	rows, err := d.Pool.Query(ctx, `SELECT id, COALESCE(host(host), ''), COALESCE(host(peer), '') FROM alerts WHERE state <> 'resolved'`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id         int64
		host, peer string
	}
	var alerts []row
	ipSet := map[string]bool{}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.host, &r.peer); err != nil {
			rows.Close()
			return 0, err
		}
		alerts = append(alerts, r)
		for _, ip := range []string{r.host, r.peer} {
			if ip != "" {
				ipSet[ip] = true
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	names := map[string][]string{}
	if set.HasNames() {
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}
		if names, err = d.NamesForIPs(ctx, ips); err != nil {
			return 0, err
		}
	}
	var ids []int64
	for _, r := range alerts {
		if _, ok := set.Match(r.host, names[r.host]); ok {
			ids = append(ids, r.id)
			continue
		}
		if _, ok := set.Match(r.peer, names[r.peer]); ok {
			ids = append(ids, r.id)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	tag, err := d.Pool.Exec(ctx, `UPDATE alerts SET state = 'resolved', resolved_at = now() WHERE id = ANY($1::bigint[])`, ids)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
