package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := `# comment
8.8.8.8
1.2.3.0/24 ; inline
203.0.113.5,extra,columns
2024-01-01 00:00:00,45.9.148.7,443
10.0.0.1
192.168.1.1
2001:db8::/32
not-an-ip
8.8.8.8
`
	nets, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	// 8.8.8.8/32, 1.2.3.0/24, 203.0.113.5/32, 45.9.148.7/32 (from column 2), 2001:db8::/32 ; privates + garbage + dup dropped
	got := strings.Join(nets, " ")
	if len(nets) != 5 || !strings.Contains(got, "8.8.8.8/32") || !strings.Contains(got, "1.2.3.0/24") || !strings.Contains(got, "45.9.148.7/32") || strings.Contains(got, "10.0.0.1") || strings.Contains(got, "192.168") {
		t.Errorf("parse: %v", nets)
	}
}

func TestParseThreatFoxCSV(t *testing.T) {
	in := `################################################################
# ThreatFox IOCs: recent ip-port - CSV format                  #
################################################################
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type"
"2026-08-29 19:47:14", "1891174", "94.228.166.168:56003", "ip:port", "botnet_cc", "win.pure_rat"
"2026-08-29 19:46:41", "1891173", "54.199.206.9:21672", "ip:port", "botnet_cc", "win.asyncrat"
"2026-08-29 19:46:40", "1891172", "[2001:db8::7]:443", "ip:port", "botnet_cc", "x"
"2026-08-29 19:46:40", "1891171", "192.168.1.5:443", "ip:port", "botnet_cc", "private-dropped"
`
	nets, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(nets, " ")
	if len(nets) != 3 || !strings.Contains(got, "94.228.166.168/32") || !strings.Contains(got, "54.199.206.9/32") || !strings.Contains(got, "2001:db8::7/128") {
		t.Errorf("threatfox parse: %v", nets)
	}
}

func TestFetchDeprecatedFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# abuse.ch SSLBL Botnet C2 IP Blacklist\n#\n# ATTENTION: This list has been deprecated on 2025-01-03\n#\n"))
	}))
	defer srv.Close()
	f := &Fetcher{Client: srv.Client()}
	_, err := f.Fetch(context.Background(), "sslbl", srv.URL)
	if err == nil || !strings.Contains(err.Error(), "deprecated upstream") || !strings.Contains(err.Error(), "2025-01-03") {
		t.Fatalf("expected a deprecation error, got %v", err)
	}
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("# nothing here\n")) }))
	defer empty.Close()
	if _, err := f.Fetch(context.Background(), "x", empty.URL); err == nil || !strings.Contains(err.Error(), "zero entries") {
		t.Fatalf("expected zero-entries error, got %v", err)
	}
}
