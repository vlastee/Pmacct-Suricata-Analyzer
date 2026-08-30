package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
)

// mockVT mimics VirusTotal's /api/v3/ip_addresses/{ip} endpoint.
type mockVT struct {
	*httptest.Server
	calls   atomic.Int64
	mu      sync.Mutex
	order   []string // IPs in the order they were requested
	quotaAt int64    // when > 0, respond 429 after this many calls
}

func (m *mockVT) requested() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.order...)
}

func newMockVT() *mockVT {
	m := &mockVT{}
	stats := func(mal, sus, harm, und int) map[string]any {
		return map[string]any{"malicious": mal, "suspicious": sus, "harmless": harm, "undetected": und, "timeout": 0}
	}
	data := map[string]map[string]any{
		"8.8.8.8":     {"asn": 15169, "as_owner": "GOOGLE", "country": "US", "network": "8.8.8.0/24", "reputation": 500, "tags": []string{}, "last_analysis_date": 1750000000, "last_analysis_stats": stats(0, 0, 60, 30)},
		"1.1.1.1":     {"asn": 13335, "as_owner": "CLOUDFLARENET", "country": "AU", "network": "1.1.1.0/24", "reputation": 300, "tags": []string{}, "last_analysis_date": 1750000000, "last_analysis_stats": stats(0, 0, 61, 29)},
		"203.0.113.5": {"asn": 64496, "as_owner": "EVIL-NET", "country": "ZZ", "network": "203.0.113.0/24", "reputation": -40, "tags": []string{"malware", "c2"}, "last_analysis_date": 1750000000, "last_analysis_stats": stats(7, 2, 40, 41)},
	}
	files := map[string]map[string]any{
		// A hash 41 engines flag; everything else is "never submitted" (404).
		"1111111111111111111111111111111111111111111111111111111111111111": {"meaningful_name": "evil.exe", "names": []string{"evil.exe"}, "type_description": "Win32 EXE",
			"first_submission_date": 1700000000, "last_analysis_date": 1750000000, "last_analysis_stats": stats(41, 1, 0, 30),
			"signature_info": map[string]any{"signers": "Contoso Ltd; DigiCert"}, "popular_threat_classification": map[string]any{"suggested_threat_label": "trojan.agent/redline"}},
	}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := m.calls.Add(1)
		if h, ok := strings.CutPrefix(r.URL.Path, "/api/v3/files/"); ok {
			m.mu.Lock()
			m.order = append(m.order, "file:"+h)
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if r.Header.Get("x-apikey") != "test-key" {
				w.WriteHeader(401)
				return
			}
			if d, ok := files[h]; ok {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": h, "type": "file", "attributes": d}})
				return
			}
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "NotFoundError", "message": "not found"}})
			return
		}
		ip := strings.TrimPrefix(r.URL.Path, "/api/v3/ip_addresses/")
		m.mu.Lock()
		m.order = append(m.order, ip)
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("x-apikey") != "test-key" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "WrongCredentialsError", "message": "bad key"}})
			return
		}
		if m.quotaAt > 0 && n > m.quotaAt {
			w.WriteHeader(429)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "QuotaExceededError", "message": "quota exceeded"}})
			return
		}
		if d, ok := data[ip]; ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": ip, "type": "ip_address", "attributes": d}})
			return
		}
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "NotFoundError", "message": "not found"}})
	}))
	return m
}
