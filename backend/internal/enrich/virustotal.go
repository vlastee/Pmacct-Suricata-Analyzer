package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// ErrQuotaExceeded is returned when VirusTotal reports the API quota is exhausted (HTTP 429).
// The scheduler stops the current pass when it sees this.
var ErrQuotaExceeded = errors.New("virustotal quota exceeded")

// VirusTotal queries the VirusTotal v3 IP address endpoint.
type VirusTotal struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

// Name identifies the provider.
func (p *VirusTotal) Name() string { return "virustotal" }

type vtResp struct {
	Data struct {
		Attributes struct {
			ASN               int      `json:"asn"`
			ASOwner           string   `json:"as_owner"`
			Country           string   `json:"country"`
			Network           string   `json:"network"`
			Reputation        int      `json:"reputation"`
			Tags              []string `json:"tags"`
			LastAnalysisDate  int64    `json:"last_analysis_date"`
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Lookup fetches the reputation summary for an IP. An unknown IP (404) yields an "ok" result
// with zero counts, so it is not retried until the refresh interval.
func (p *VirusTotal) Lookup(ctx context.Context, ip string) (*db.VTResult, error) {
	u := strings.TrimRight(p.BaseURL, "/") + "/api/v3/ip_addresses/" + url.PathEscape(ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", p.APIKey)
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
		return nil, fmt.Errorf("virustotal: invalid API key (http %d)", resp.StatusCode)
	case http.StatusNotFound:
		zero := 0
		return &db.VTResult{Malicious: &zero, Suspicious: &zero, Harmless: &zero, Undetected: &zero, Status: "ok", Tags: []string{}}, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("virustotal http %d", resp.StatusCode)
	}
	var r vtResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("virustotal decode: %w", err)
	}
	if r.Error != nil {
		if r.Error.Code == "QuotaExceededError" {
			return nil, ErrQuotaExceeded
		}
		return nil, fmt.Errorf("virustotal: %s: %s", r.Error.Code, r.Error.Message)
	}
	a := r.Data.Attributes
	st := a.LastAnalysisStats
	res := &db.VTResult{
		Malicious: &st.Malicious, Suspicious: &st.Suspicious, Harmless: &st.Harmless, Undetected: &st.Undetected,
		Reputation: &a.Reputation, Tags: a.Tags, Network: sp(a.Network), Status: "ok",
		ASOrg: sp(a.ASOwner), CountryCode: sp(a.Country),
	}
	if res.Tags == nil {
		res.Tags = []string{}
	}
	if a.ASN != 0 {
		asn := fmt.Sprintf("AS%d", a.ASN)
		res.ASN = &asn
	}
	if a.LastAnalysisDate > 0 {
		t := time.Unix(a.LastAnalysisDate, 0).UTC()
		res.LastAnalysis = &t
	}
	return res, nil
}

type vtFileResp struct {
	Data struct {
		Attributes struct {
			MeaningfulName    string   `json:"meaningful_name"`
			Names             []string `json:"names"`
			TypeDescription   string   `json:"type_description"`
			FirstSubmission   int64    `json:"first_submission_date"`
			LastAnalysisDate  int64    `json:"last_analysis_date"`
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			SignatureInfo struct {
				Product  string `json:"product"`
				Signers  string `json:"signers"`
				Verified string `json:"verified"`
			} `json:"signature_info"`
			PopularThreat struct {
				SuggestedThreatLabel string `json:"suggested_threat_label"`
			} `json:"popular_threat_classification"`
		} `json:"attributes"`
	} `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// LookupFile fetches the file report for a SHA-256 (GET /api/v3/files/{hash}). Only the hash
// is sent; the file itself never leaves the machine. A hash VirusTotal has never seen (404)
// yields status "unknown" — itself a useful fact.
func (p *VirusTotal) LookupFile(ctx context.Context, sha256 string) (*db.FileVT, error) {
	u := strings.TrimRight(p.BaseURL, "/") + "/api/v3/files/" + url.PathEscape(strings.ToLower(sha256))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", p.APIKey)
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
		return nil, fmt.Errorf("virustotal: invalid API key (http %d)", resp.StatusCode)
	case http.StatusNotFound:
		return &db.FileVT{Status: "unknown", Names: []string{}, Signers: []string{}}, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("virustotal http %d", resp.StatusCode)
	}
	var r vtFileResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("virustotal decode: %w", err)
	}
	if r.Error != nil {
		if r.Error.Code == "QuotaExceededError" {
			return nil, ErrQuotaExceeded
		}
		if r.Error.Code == "NotFoundError" {
			return &db.FileVT{Status: "unknown", Names: []string{}, Signers: []string{}}, nil
		}
		return nil, fmt.Errorf("virustotal: %s: %s", r.Error.Code, r.Error.Message)
	}
	a := r.Data.Attributes
	st := a.LastAnalysisStats
	res := &db.FileVT{Status: "ok", Malicious: &st.Malicious, Suspicious: &st.Suspicious, Harmless: &st.Harmless, Undetected: &st.Undetected,
		Label: a.PopularThreat.SuggestedThreatLabel, Type: a.TypeDescription, Names: []string{}, Signers: []string{}}
	if a.MeaningfulName != "" {
		res.Names = append(res.Names, a.MeaningfulName)
	}
	for _, n := range a.Names {
		if n != "" && n != a.MeaningfulName && len(res.Names) < 8 {
			res.Names = append(res.Names, n)
		}
	}
	for _, sg := range strings.Split(a.SignatureInfo.Signers, ";") {
		if sg = strings.TrimSpace(sg); sg != "" {
			res.Signers = append(res.Signers, sg)
		}
	}
	if a.FirstSubmission > 0 {
		t := time.Unix(a.FirstSubmission, 0).UTC()
		res.FirstSeen = &t
	}
	if a.LastAnalysisDate > 0 {
		t := time.Unix(a.LastAnalysisDate, 0).UTC()
		res.LastAnalysis = &t
	}
	return res, nil
}
