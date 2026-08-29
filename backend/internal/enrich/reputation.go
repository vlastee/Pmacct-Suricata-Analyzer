package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// ReputationProvider is a per-IP reputation source with a quota (AbuseIPDB, GreyNoise).
type ReputationProvider interface {
	Name() string
	Lookup(ctx context.Context, ip string) (*db.Reputation, error)
}

// ---- AbuseIPDB ----

// AbuseIPDB queries /api/v2/check. Free tier: 1000 checks/day.
type AbuseIPDB struct {
	BaseURL  string
	APIKey   string
	Client   *http.Client
	MinScore int // abuseConfidenceScore at/above which the IP is flagged (default 50)
}

// Name identifies the source.
func (p *AbuseIPDB) Name() string { return "abuseipdb" }

type abuseResp struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		TotalReports         int    `json:"totalReports"`
		NumDistinctUsers     int    `json:"numDistinctUsers"`
		LastReportedAt       string `json:"lastReportedAt"`
		UsageType            string `json:"usageType"`
		ISP                  string `json:"isp"`
		Domain               string `json:"domain"`
		CountryCode          string `json:"countryCode"`
		IsTor                bool   `json:"isTor"`
		IsWhitelisted        *bool  `json:"isWhitelisted"`
	} `json:"data"`
	Errors []struct {
		Detail string `json:"detail"`
		Status int    `json:"status"`
	} `json:"errors"`
}

// Lookup checks one IP.
func (p *AbuseIPDB) Lookup(ctx context.Context, ip string) (*db.Reputation, error) {
	u := strings.TrimRight(p.BaseURL, "/") + "/api/v2/check?ipAddress=" + url.QueryEscape(ip) + "&maxAgeInDays=90"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", p.APIKey)
	req.Header.Set("Accept", "application/json")
	c := p.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, ErrQuotaExceeded
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("abuseipdb: invalid API key (http %d)", resp.StatusCode)
	}
	var r abuseResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("abuseipdb decode: %w", err)
	}
	if len(r.Errors) > 0 {
		return nil, fmt.Errorf("abuseipdb: %s", r.Errors[0].Detail)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb http %d", resp.StatusCode)
	}
	min := p.MinScore
	if min == 0 {
		min = 50
	}
	score := r.Data.AbuseConfidenceScore
	data, _ := json.Marshal(map[string]any{"score": score, "reports": r.Data.TotalReports, "reporters": r.Data.NumDistinctUsers,
		"last_reported": r.Data.LastReportedAt, "usage_type": r.Data.UsageType, "isp": r.Data.ISP, "domain": r.Data.Domain,
		"country": r.Data.CountryCode, "is_tor": r.Data.IsTor, "whitelisted": r.Data.IsWhitelisted})
	return &db.Reputation{Source: p.Name(), Status: "ok", Score: &score, Flagged: score >= min || r.Data.IsTor, Data: data}, nil
}

// ---- GreyNoise community ----

// GreyNoise queries the community endpoint. Flags IPs classified malicious.
type GreyNoise struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

// Name identifies the source.
func (p *GreyNoise) Name() string { return "greynoise" }

type gnResp struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

// Lookup checks one IP. 404 = never observed (stored as ok/unflagged).
func (p *GreyNoise) Lookup(ctx context.Context, ip string) (*db.Reputation, error) {
	u := strings.TrimRight(p.BaseURL, "/") + "/v3/community/" + url.PathEscape(ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("key", p.APIKey)
	req.Header.Set("Accept", "application/json")
	c := p.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return nil, ErrQuotaExceeded
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("greynoise: invalid API key (http %d)", resp.StatusCode)
	case http.StatusNotFound:
		zero := 0
		data, _ := json.Marshal(map[string]any{"observed": false})
		return &db.Reputation{Source: p.Name(), Status: "ok", Score: &zero, Flagged: false, Data: data}, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("greynoise http %d", resp.StatusCode)
	}
	var r gnResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("greynoise decode: %w", err)
	}
	score := 0
	switch r.Classification {
	case "malicious":
		score = 100
	case "unknown":
		if r.Noise {
			score = 40
		}
	}
	data, _ := json.Marshal(map[string]any{"observed": true, "noise": r.Noise, "riot": r.Riot, "classification": r.Classification,
		"name": r.Name, "link": r.Link, "last_seen": r.LastSeen})
	return &db.Reputation{Source: p.Name(), Status: "ok", Score: &score, Flagged: r.Classification == "malicious", Data: data}, nil
}
