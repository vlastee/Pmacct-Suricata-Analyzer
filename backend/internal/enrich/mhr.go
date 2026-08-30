package enrich

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// MHR queries the Team Cymru Malware Hash Registry over DNS: a TXT record for
// <md5|sha1>.malware.hash.cymru.com answers "<unix-timestamp> <detection-percent>" when the
// hash is known malware; NXDOMAIN means it is not listed. Free, keyless, no submission of the
// file itself — only its hash.
type MHR struct {
	Zone      string                                                   // default malware.hash.cymru.com
	LookupTXT func(ctx context.Context, name string) ([]string, error) // nil = net.DefaultResolver
	Timeout   time.Duration
}

func (m *MHR) Name() string { return "cymru-mhr" }

func (m *MHR) zone() string {
	if m.Zone != "" {
		return strings.Trim(m.Zone, ".")
	}
	return "malware.hash.cymru.com"
}

// Lookup checks one hash (MD5 or SHA-1, hex).
func (m *MHR) Lookup(ctx context.Context, hash string) (*db.FileMHR, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if len(hash) != 32 && len(hash) != 40 {
		return nil, fmt.Errorf("mhr: need an md5 or sha1, got %d hex chars", len(hash))
	}
	timeout := m.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	lookup := m.LookupTXT
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}
	txts, err := lookup(ctx, hash+"."+m.zone())
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return &db.FileMHR{Status: "clean"}, nil
		}
		return nil, err
	}
	for _, t := range txts {
		f := strings.Fields(t)
		if len(f) < 2 {
			continue
		}
		ts, err1 := strconv.ParseInt(f[0], 10, 64)
		pct, err2 := strconv.Atoi(strings.TrimSuffix(f[1], "%"))
		if err1 != nil || err2 != nil {
			continue
		}
		seen := time.Unix(ts, 0).UTC()
		return &db.FileMHR{Status: "listed", Detection: &pct, LastSeen: &seen}, nil
	}
	return &db.FileMHR{Status: "clean"}, nil
}
