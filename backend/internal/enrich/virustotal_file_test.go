package enrich

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVirusTotalLookupFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "k" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/v3/files/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":
			w.Write([]byte(`{"data":{"attributes":{"meaningful_name":"evil.exe","names":["evil.exe","setup.exe"],"type_description":"Win32 EXE",
"first_submission_date":1700000000,"last_analysis_date":1750000000,"last_analysis_stats":{"malicious":41,"suspicious":1,"harmless":0,"undetected":30},
"signature_info":{"product":"X","signers":"Contoso Ltd; DigiCert; DigiCert Root","verified":"Signed"},
"popular_threat_classification":{"suggested_threat_label":"trojan.agent/redline"}}}}`))
		case "/api/v3/files/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":
			w.WriteHeader(404)
			w.Write([]byte(`{"error":{"code":"NotFoundError","message":"File not found"}}`))
		case "/api/v3/files/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc":
			w.WriteHeader(429)
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	vt := &VirusTotal{BaseURL: srv.URL, APIKey: "k"}
	ctx := context.Background()
	got, err := vt.LookupFile(ctx, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil || got.Status != "ok" || *got.Malicious != 41 || got.Label != "trojan.agent/redline" || got.Type != "Win32 EXE" {
		t.Fatalf("ok: %+v %v", got, err)
	}
	if len(got.Names) != 2 || got.Names[0] != "evil.exe" || len(got.Signers) != 3 || got.Signers[0] != "Contoso Ltd" || got.FirstSeen == nil || got.LastAnalysis == nil {
		t.Errorf("names/signers/dates: %+v", got)
	}
	got, err = vt.LookupFile(ctx, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil || got.Status != "unknown" {
		t.Fatalf("404 should be unknown: %+v %v", got, err)
	}
	if _, err = vt.LookupFile(ctx, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"); !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("429 should be quota: %v", err)
	}
	if _, err = vt.LookupFile(ctx, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"); err == nil {
		t.Error("500 should fail")
	}
}
