package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
)

// mockIPAPI mimics ip-api.com's /json/{ip} endpoint for a fixed set of addresses.
type mockIPAPI struct {
	*httptest.Server
	calls atomic.Int64
}

func newMockIPAPI() *mockIPAPI {
	m := &mockIPAPI{}
	data := map[string]map[string]any{
		"8.8.8.8": {"status": "success", "country": "United States", "countryCode": "US", "regionName": "California",
			"city": "Mountain View", "lat": 37.386, "lon": -122.0838, "timezone": "America/Los_Angeles", "isp": "Google LLC",
			"org": "Google Public DNS", "as": "AS15169 Google LLC", "asname": "GOOGLE", "reverse": "dns.google",
			"mobile": false, "proxy": false, "hosting": true},
		"1.1.1.1": {"status": "success", "country": "Australia", "countryCode": "AU", "regionName": "Queensland",
			"city": "South Brisbane", "lat": -27.4766, "lon": 153.0166, "timezone": "Australia/Brisbane", "isp": "Cloudflare, Inc",
			"org": "APNIC and Cloudflare DNS Resolver project", "as": "AS13335 Cloudflare, Inc.", "asname": "CLOUDFLARENET",
			"reverse": "one.one.one.one", "mobile": false, "proxy": false, "hosting": false},
	}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.calls.Add(1)
		ip := strings.TrimPrefix(r.URL.Path, "/json/")
		w.Header().Set("Content-Type", "application/json")
		if d, ok := data[ip]; ok {
			_ = json.NewEncoder(w).Encode(d)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "fail", "message": "reserved range", "query": ip})
	}))
	return m
}
