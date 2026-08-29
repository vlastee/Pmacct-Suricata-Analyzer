package enrich

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVirusTotalLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "k" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/v3/ip_addresses/203.0.113.5":
			w.Write([]byte(`{"data":{"id":"203.0.113.5","type":"ip_address","attributes":{"asn":64496,"as_owner":"EVIL","country":"ZZ","network":"203.0.113.0/24","reputation":-10,"tags":["malware"],"last_analysis_date":1750000000,"last_analysis_stats":{"malicious":5,"suspicious":1,"harmless":50,"undetected":30,"timeout":0}}}}`))
		case "/api/v3/ip_addresses/198.51.100.1":
			w.WriteHeader(404)
			w.Write([]byte(`{"error":{"code":"NotFoundError","message":"not found"}}`))
		case "/api/v3/ip_addresses/9.9.9.9":
			w.WriteHeader(429)
			w.Write([]byte(`{"error":{"code":"QuotaExceededError","message":"quota"}}`))
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	p := &VirusTotal{BaseURL: srv.URL, APIKey: "k"}
	ctx := context.Background()
	r, err := p.Lookup(ctx, "203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	if *r.Malicious != 5 || *r.Suspicious != 1 || *r.ASN != "AS64496" || *r.CountryCode != "ZZ" || r.Tags[0] != "malware" || r.LastAnalysis == nil || r.Status != "ok" {
		t.Errorf("parse: %+v", r)
	}
	r, err = p.Lookup(ctx, "198.51.100.1")
	if err != nil || r.Status != "ok" || *r.Malicious != 0 {
		t.Errorf("404 should be ok/zero: %v %+v", err, r)
	}
	if _, err := p.Lookup(ctx, "9.9.9.9"); !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("429 should be ErrQuotaExceeded, got %v", err)
	}
	if _, err := p.Lookup(ctx, "1.2.3.4"); err == nil {
		t.Errorf("500 should error")
	}
	bad := &VirusTotal{BaseURL: srv.URL, APIKey: "wrong"}
	if _, err := bad.Lookup(ctx, "203.0.113.5"); err == nil {
		t.Errorf("401 should error")
	}
}
