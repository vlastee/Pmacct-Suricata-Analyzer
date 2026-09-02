package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAbuseIPDB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "k" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Query().Get("ipAddress") == "9.9.9.9" {
			w.WriteHeader(429)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ipAddress": "1.2.3.4", "abuseConfidenceScore": 88, "totalReports": 12, "isTor": false}})
	}))
	defer srv.Close()
	p := &AbuseIPDB{BaseURL: srv.URL, APIKey: "k"}
	r, err := p.Lookup(context.Background(), "1.2.3.4")
	if err != nil || !r.Flagged || *r.Score != 88 {
		t.Errorf("lookup: %v %+v", err, r)
	}
	if _, err := p.Lookup(context.Background(), "9.9.9.9"); !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("429 should be quota, got %v", err)
	}
	bad := &AbuseIPDB{BaseURL: srv.URL, APIKey: "wrong"}
	if _, err := bad.Lookup(context.Background(), "1.2.3.4"); err == nil {
		t.Error("401 should error")
	}
}

func TestGreyNoise(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/community/6.6.6.6":
			_ = json.NewEncoder(w).Encode(map[string]any{"ip": "6.6.6.6", "noise": true, "classification": "malicious", "name": "Bad Scanner"})
		case "/v3/community/7.7.7.7":
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	p := &GreyNoise{BaseURL: srv.URL, APIKey: "k"}
	r, err := p.Lookup(context.Background(), "6.6.6.6")
	if err != nil || !r.Flagged || *r.Score != 100 {
		t.Errorf("malicious: %v %+v", err, r)
	}
	r, err = p.Lookup(context.Background(), "7.7.7.7")
	if err != nil || r.Flagged {
		t.Errorf("404 should be ok/unflagged: %v %+v", err, r)
	}
}

func TestOTX(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") != "k" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/v1/indicators/IPv4/8.8.8.8/general":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"reputation": 0,
				"pulse_info": map[string]any{"count": 0, "pulses": []any{}},
			})
		case "/api/v1/indicators/IPv4/6.6.6.6/general":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"reputation": -5,
				"pulse_info": map[string]any{"count": 3, "pulses": []map[string]any{{"name": "Bad Botnet"}}},
			})
		case "/api/v1/indicators/IPv4/9.9.9.9/general":
			w.WriteHeader(429)
		}
	}))
	defer srv.Close()
	p := &OTX{BaseURL: srv.URL, APIKey: "k"}

	r, err := p.Lookup(context.Background(), "8.8.8.8")
	if err != nil || r.Flagged || *r.Score != 0 {
		t.Errorf("clean ip: %v %+v", err, r)
	}

	r, err = p.Lookup(context.Background(), "6.6.6.6")
	if err != nil || !r.Flagged || *r.Score != 3 {
		t.Errorf("malicious: %v %+v", err, r)
	}

	if _, err := p.Lookup(context.Background(), "9.9.9.9"); !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("429 should be quota, got %v", err)
	}

	bad := &OTX{BaseURL: srv.URL, APIKey: "wrong"}
	if _, err := bad.Lookup(context.Background(), "8.8.8.8"); err == nil {
		t.Error("401 should error")
	}
}
