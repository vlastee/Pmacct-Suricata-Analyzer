// Package feeds downloads bulk threat-intelligence IP lists and stores them for local matching.
package feeds

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// Fetcher downloads and parses feeds.
type Fetcher struct {
	DB       *db.DB
	Feeds    map[string]string
	Client   *http.Client
	Interval time.Duration

	mu      sync.Mutex
	lastRun time.Time
	results map[string]Result
}

// Result summarises one feed refresh.
type Result struct {
	Entries int       `json:"entries"`
	Error   string    `json:"error,omitempty"`
	At      time.Time `json:"at"`
	URL     string    `json:"url"`
}

// Parse extracts IPs/CIDRs from a text list: one entry per line, `#`/`;` comments, extra columns ignored.
// Single addresses become /32 (/128) networks; private/reserved ranges are dropped.
func Parse(r io.Reader) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Scan every whitespace/comma-separated column for the first IP or CIDR, so lists that
		// put the address in a later column (e.g. abuse.ch SSLBL "Firstseen,DstIP,DstPort") work.
		var p netip.Prefix
		found := false
		for _, t := range strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' }) {
			if pf, err := netip.ParsePrefix(t); err == nil {
				p, found = pf.Masked(), true
				break
			}
			if a, err := netip.ParseAddr(t); err == nil {
				a = a.Unmap()
				p, found = netip.PrefixFrom(a, a.BitLen()), true
				break
			}
		}
		if !found {
			continue
		}
		a := p.Addr()
		if a.IsPrivate() || a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() || a.IsLinkLocalUnicast() {
			continue
		}
		s := p.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, sc.Err()
}

// Fetch downloads one feed and replaces its entries.
func (f *Fetcher) Fetch(ctx context.Context, name, url string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "pmacct-analyzer/1.0 (+threat feed refresh)")
	c := f.Client
	if c == nil {
		c = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("http %d", resp.StatusCode)
	}
	nets, err := Parse(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return 0, err
	}
	if len(nets) == 0 {
		return 0, fmt.Errorf("feed parsed to zero entries; keeping previous list")
	}
	if err := f.DB.ReplaceThreatList(ctx, name, nets); err != nil {
		return 0, err
	}
	return len(nets), nil
}

// RefreshAll fetches every configured feed. Failures are logged and recorded, not fatal.
func (f *Fetcher) RefreshAll(ctx context.Context) {
	names := make([]string, 0, len(f.Feeds))
	for n := range f.Feeds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if ctx.Err() != nil {
			return
		}
		url := f.Feeds[name]
		n, err := f.Fetch(ctx, name, url)
		res := Result{Entries: n, At: time.Now(), URL: url}
		if err != nil {
			res.Error = err.Error()
			slog.Warn("threat feed refresh failed", "feed", name, "err", err)
		} else {
			slog.Info("threat feed refreshed", "feed", name, "entries", n)
		}
		f.mu.Lock()
		if f.results == nil {
			f.results = map[string]Result{}
		}
		f.results[name] = res
		f.lastRun = time.Now()
		f.mu.Unlock()
	}
}

// Run refreshes on an interval until ctx is done.
func (f *Fetcher) Run(ctx context.Context) {
	if len(f.Feeds) == 0 {
		return
	}
	f.RefreshAll(ctx)
	t := time.NewTicker(f.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f.RefreshAll(ctx)
		}
	}
}

// Status returns the last result per feed.
func (f *Fetcher) Status() (time.Time, map[string]Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]Result{}
	for k, v := range f.results {
		out[k] = v
	}
	return f.lastRun, out
}
