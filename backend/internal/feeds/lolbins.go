package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// LOLBins refreshes the LOLBAS (Windows) and GTFOBins (Unix) catalogues of legitimate system
// binaries that attackers abuse, so Explain can flag them even when they are not in the
// built-in knowledge base. An empty URL disables that source.
type LOLBins struct {
	DB          *db.DB
	Client      *http.Client
	LOLBASURL   string
	GTFOBinsURL string
	Every       time.Duration // default 24h

	mu   sync.Mutex
	last time.Time
}

func (l *LOLBins) every() time.Duration {
	if l.Every > 0 {
		return l.Every
	}
	return 24 * time.Hour
}

// Due reports whether a refresh should run now.
func (l *LOLBins) Due() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Since(l.last) >= l.every()
}

// Refresh downloads both catalogues; the result per source uses the feed Result shape so it
// shows up next to the threat feeds.
func (l *LOLBins) Refresh(ctx context.Context) map[string]Result {
	out := map[string]Result{}
	l.mu.Lock()
	l.last = time.Now()
	l.mu.Unlock()
	for _, src := range []struct {
		name, url string
		parse     func(io.Reader) ([]db.LOLBin, error)
	}{{"lolbas", l.LOLBASURL, ParseLOLBAS}, {"gtfobins", l.GTFOBinsURL, ParseGTFOBins}} {
		if src.url == "" || ctx.Err() != nil {
			continue
		}
		n, err := l.fetch(ctx, src.name, src.url, src.parse)
		res := Result{Entries: n, At: time.Now(), URL: src.url}
		if err != nil {
			res.Error = err.Error()
			slog.Warn("lolbins refresh failed", "source", src.name, "err", err)
		} else {
			slog.Info("lolbins refreshed", "source", src.name, "entries", n)
		}
		out[src.name] = res
	}
	return out
}

func (l *LOLBins) fetch(ctx context.Context, name, url string, parse func(io.Reader) ([]db.LOLBin, error)) (int, error) {
	client := l.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "pmacct-analyzer/lolbins")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("http %d", resp.StatusCode)
	}
	items, err := parse(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return 0, err
	}
	if len(items) < 20 {
		return 0, fmt.Errorf("catalogue parsed to only %d entries; keeping the previous list", len(items))
	}
	if l.DB != nil {
		if err := l.DB.ReplaceLOLBins(ctx, name, items); err != nil {
			return 0, err
		}
	}
	return len(items), nil
}

// ParseLOLBAS reads the LOLBAS project's api/lolbas.json (an array of binaries with Commands).
func ParseLOLBAS(r io.Reader) ([]db.LOLBin, error) {
	var raw []struct {
		Name        string `json:"Name"`
		Description string `json:"Description"`
		Commands    []struct {
			Category string `json:"Category"`
			MitreID  string `json:"MitreID"`
		} `json:"Commands"`
		FullPath []struct {
			Path string `json:"Path"`
		} `json:"Full_Path"`
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("lolbas: %w", err)
	}
	out := make([]db.LOLBin, 0, len(raw))
	for _, b := range raw {
		if b.Name == "" {
			continue
		}
		funcs, mitre := map[string]bool{}, map[string]bool{}
		for _, c := range b.Commands {
			if c.Category != "" {
				funcs[c.Category] = true
			}
			if c.MitreID != "" {
				mitre[c.MitreID] = true
			}
		}
		var paths []string
		for _, p := range b.FullPath {
			if p.Path != "" && p.Path != "N/A" {
				paths = append(paths, p.Path)
			}
		}
		url := b.URL
		if url == "" {
			url = "https://lolbas-project.github.io/lolbas/Binaries/" + strings.TrimSuffix(b.Name, ".exe") + "/"
		}
		out = append(out, db.LOLBin{Source: "lolbas", Name: db.LOLBinName(b.Name), Display: b.Name, Description: strings.TrimSpace(b.Description),
			Functions: keys(funcs), Paths: paths, Mitre: keys(mitre), URL: url})
	}
	return out, nil
}

// ParseGTFOBins reads gtfobins.org/api.json: {"functions": {id: {label, description, mitre}},
// "executables": {name: {"functions": {id: [...]}}}}.
func ParseGTFOBins(r io.Reader) ([]db.LOLBin, error) {
	var raw struct {
		Functions map[string]struct {
			Label       string   `json:"label"`
			Description string   `json:"description"`
			Mitre       []string `json:"mitre"`
		} `json:"functions"`
		Executables map[string]struct {
			Description string                     `json:"description"`
			Functions   map[string]json.RawMessage `json:"functions"`
		} `json:"executables"`
	}
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("gtfobins: %w", err)
	}
	out := make([]db.LOLBin, 0, len(raw.Executables))
	for name, e := range raw.Executables {
		var funcs, mitre []string
		seen := map[string]bool{}
		for id := range e.Functions {
			label := id
			if f, ok := raw.Functions[id]; ok {
				if f.Label != "" {
					label = f.Label
				}
				for _, m := range f.Mitre {
					if !seen[m] {
						seen[m] = true
						mitre = append(mitre, m)
					}
				}
			}
			funcs = append(funcs, label)
		}
		sort.Strings(funcs)
		sort.Strings(mitre)
		desc := strings.TrimSpace(e.Description)
		if desc == "" {
			desc = "Listed by GTFOBins: a Unix binary that can be abused to " + strings.ToLower(strings.Join(funcs, ", ")) + "."
		}
		out = append(out, db.LOLBin{Source: "gtfobins", Name: db.LOLBinName(name), Display: name, Description: desc, Functions: funcs, Paths: []string{}, Mitre: mitre,
			URL: "https://gtfobins.org/gtfobins/" + name + "/"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
