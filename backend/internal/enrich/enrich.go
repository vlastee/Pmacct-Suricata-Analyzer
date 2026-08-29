// Package enrich looks up information about external IP addresses from internet sources.
package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// Provider fetches enrichment for one IP.
type Provider interface {
	Name() string
	Lookup(ctx context.Context, ip string) (*db.IPInfo, error)
}

// Enricher combines a primary provider with optional reverse DNS.
type Enricher struct {
	Provider   Provider
	ReverseDNS bool
	Resolver   interface {
		LookupAddr(ctx context.Context, addr string) ([]string, error)
	}
}

// Lookup runs the provider and (optionally) reverse DNS and returns a merged record.
// The returned record always has Status set: "ok" or "failed" with Error.
func (e *Enricher) Lookup(ctx context.Context, ip string) *db.IPInfo {
	info, err := e.Provider.Lookup(ctx, ip)
	if err != nil {
		msg := err.Error()
		info = &db.IPInfo{IP: ip, Status: "failed", Error: &msg}
	} else {
		info.IP = ip
		info.Status = "ok"
		src := e.Provider.Name()
		info.Source = &src
	}
	if e.ReverseDNS && info.Hostname == nil {
		r := e.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		names, derr := r.LookupAddr(dctx, ip)
		cancel()
		if derr == nil && len(names) > 0 {
			h := strings.TrimSuffix(names[0], ".")
			info.Hostname = &h
		}
	}
	return info
}

// ---- ip-api.com ----

// IPAPI implements Provider using the ip-api.com JSON endpoint (free, no key, HTTP only, 45 req/min).
type IPAPI struct {
	BaseURL string
	Client  *http.Client
}

func (p *IPAPI) Name() string { return "ip-api.com" }

type ipapiResp struct {
	Status      string  `json:"status"`
	Message     string  `json:"message"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	ASName      string  `json:"asname"`
	Reverse     string  `json:"reverse"`
	Mobile      bool    `json:"mobile"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
}

// Lookup queries ip-api.com.
func (p *IPAPI) Lookup(ctx context.Context, ip string) (*db.IPInfo, error) {
	u := strings.TrimRight(p.BaseURL, "/") + "/json/" + url.PathEscape(ip) +
		"?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "pmacct-analyzer/1.0")
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("ip-api rate limited (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip-api http %d", resp.StatusCode)
	}
	var r ipapiResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("ip-api decode: %w", err)
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("ip-api: %s", nz(r.Message, "lookup failed"))
	}
	info := &db.IPInfo{
		Country: sp(r.Country), CountryCode: sp(r.CountryCode), Region: sp(r.RegionName), City: sp(r.City),
		Timezone: sp(r.Timezone), ISP: sp(r.ISP), Org: sp(r.Org), Hostname: sp(r.Reverse),
		IsHosting: &r.Hosting, IsProxy: &r.Proxy, IsMobile: &r.Mobile,
	}
	if r.Lat != 0 || r.Lon != 0 {
		info.Lat, info.Lon = &r.Lat, &r.Lon
	}
	// "AS15169 Google LLC" -> asn "AS15169", as_org "Google LLC"
	if r.AS != "" {
		parts := strings.SplitN(r.AS, " ", 2)
		info.ASN = sp(parts[0])
		if len(parts) == 2 {
			info.ASOrg = sp(parts[1])
		} else {
			info.ASOrg = sp(r.ASName)
		}
	}
	return info, nil
}

func (p *IPAPI) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return http.DefaultClient
}

// ---- ipinfo.io ----

// IPInfoIO implements Provider using ipinfo.io (needs a token for sensible quotas).
type IPInfoIO struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

func (p *IPInfoIO) Name() string { return "ipinfo.io" }

type ipinfoResp struct {
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Timezone string `json:"timezone"`
	Bogon    bool   `json:"bogon"`
	Error    *struct {
		Title string `json:"title"`
	} `json:"error"`
}

// Lookup queries ipinfo.io.
func (p *IPInfoIO) Lookup(ctx context.Context, ip string) (*db.IPInfo, error) {
	u := strings.TrimRight(p.BaseURL, "/") + "/" + url.PathEscape(ip) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}
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
		return nil, fmt.Errorf("ipinfo rate limited (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ipinfo http %d", resp.StatusCode)
	}
	var r ipinfoResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("ipinfo decode: %w", err)
	}
	if r.Error != nil {
		return nil, fmt.Errorf("ipinfo: %s", r.Error.Title)
	}
	if r.Bogon {
		return nil, fmt.Errorf("ipinfo: bogon address")
	}
	info := &db.IPInfo{Hostname: sp(r.Hostname), City: sp(r.City), Region: sp(r.Region), CountryCode: sp(r.Country), Timezone: sp(r.Timezone)}
	if r.Loc != "" {
		var lat, lon float64
		if _, err := fmt.Sscanf(r.Loc, "%f,%f", &lat, &lon); err == nil {
			info.Lat, info.Lon = &lat, &lon
		}
	}
	if r.Org != "" {
		parts := strings.SplitN(r.Org, " ", 2)
		info.ASN = sp(parts[0])
		if len(parts) == 2 {
			info.ASOrg = sp(parts[1])
			info.Org = sp(parts[1])
		}
	}
	return info, nil
}

func sp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
