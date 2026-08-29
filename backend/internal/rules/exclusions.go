package rules

import (
	"context"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// applyExclusions drops findings whose host or peer is on the global trusted list
// (alert_exclusions): exact IPs, networks, or hostname globs matched against the names
// enrichment and Suricata have learned for the address.
func (e *Engine) applyExclusions(ctx context.Context, findings []db.Finding) ([]db.Finding, error) {
	if len(findings) == 0 || e.DB == nil {
		return findings, nil
	}
	set, err := e.DB.LoadExclusions(ctx)
	if err != nil {
		return nil, err
	}
	if set.Empty() {
		return findings, nil
	}
	names := map[string][]string{}
	if set.HasNames() {
		seen := map[string]bool{}
		var ips []string
		for _, f := range findings {
			for _, ip := range []string{f.Host, f.Peer} {
				if ip != "" && !seen[ip] {
					seen[ip] = true
					ips = append(ips, ip)
				}
			}
		}
		if names, err = e.DB.NamesForIPs(ctx, ips); err != nil {
			return nil, err
		}
	}
	out := make([]db.Finding, 0, len(findings))
	for _, f := range findings {
		if _, ok := set.Match(f.Host, names[f.Host]); ok {
			continue
		}
		if _, ok := set.Match(f.Peer, names[f.Peer]); ok {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}
