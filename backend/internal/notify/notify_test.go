package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/config"
	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

func TestQuietHours(t *testing.T) {
	d := &Dispatcher{Cfg: &config.Config{NotifyQuietHours: "23-7"}}
	at := func(h int) time.Time { return time.Date(2026, 1, 2, h, 0, 0, 0, time.Local) }
	for h, want := range map[int]bool{0: true, 6: true, 7: false, 12: false, 23: true, 22: false} {
		if d.inQuietHours(at(h)) != want {
			t.Errorf("hour %d: want %v", h, want)
		}
	}
	d.Cfg.NotifyQuietHours = ""
	if d.inQuietHours(at(3)) {
		t.Error("empty quiet hours should be false")
	}
}

func TestDispatcherWebhookAndFilter(t *testing.T) {
	var mu sync.Mutex
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	cfg := &config.Config{NotifyWebhookURL: srv.URL, NotifyMinSeverity: "warning", PublicURL: "http://x"}
	d := NewDispatcher(nil, cfg, srv.Client())
	if len(d.Channels) != 1 {
		t.Fatalf("channels: %v", d.ChannelNames())
	}
	// info alert filtered out
	d.Notify(context.Background(), []db.Alert{{ID: 1, Rule: "r", Severity: "info", Title: "low"}})
	mu.Lock()
	if got != nil {
		t.Error("info alert should be filtered")
	}
	mu.Unlock()
	// warning delivered
	d.Notify(context.Background(), []db.Alert{{ID: 2, Rule: "threat_feed", Severity: "critical", Title: "bad"}})
	mu.Lock()
	if got == nil || got["severity"] != "critical" {
		t.Errorf("expected delivery, got %v", got)
	}
	mu.Unlock()
	if s := d.Stats(); s.Sent != 1 {
		t.Errorf("sent=%d", s.Sent)
	}
}

// A non-2xx reply must carry the service's own explanation (Telegram's "chat not found" etc.),
// not just the status code, so "Send test" is actionable.
func TestPostJSONErrorIncludesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("{\"ok\":false,\"error_code\":400,\n  \"description\":\"Bad Request: chat not found\"}"))
	}))
	defer srv.Close()
	ch := &Webhook{URL: srv.URL, Client: srv.Client()}
	err := ch.Send(context.Background(), Message{Title: "t", Body: "b"})
	if err == nil {
		t.Fatal("expected an error for http 400")
	}
	if !strings.Contains(err.Error(), "http 400") || !strings.Contains(err.Error(), "chat not found") {
		t.Fatalf("error should carry status and body, got: %v", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Fatalf("body should be whitespace-collapsed, got: %q", err.Error())
	}
}

func TestLabelIPs(t *testing.T) {
	cards := map[string]*ipCard{
		"10.0.0.115":  {IP: "10.0.0.115", Nick: "petro-pc"},
		"2001:db8::7": {IP: "2001:db8::7", Nick: "v6box"},
		"1.2.3.4":     {IP: "1.2.3.4"}, // no nickname: untouched
	}
	in := "10.0.0.115 contacted 1.2.3.4:443 and 10.0.0.11 and 110.0.0.115; [2001:db8::7]:22 vs 2001:db8::77"
	want := "petro-pc (10.0.0.115) contacted 1.2.3.4:443 and 10.0.0.11 and 110.0.0.115; [v6box (2001:db8::7)]:22 vs 2001:db8::77"
	if got := labelIPs(in, cards); got != want {
		t.Errorf("labelIPs:\n got %s\nwant %s", got, want)
	}
	c := &ipCard{IP: "8.8.8.8", Name: "dns.google", Geo: "US, Mountain View", Org: "Google LLC", Flags: []string{"hosting", "listed: x"}}
	if c.Detail() != "dns.google · US, Mountain View · Google LLC · hosting · listed: x" || c.Label() != "8.8.8.8" {
		t.Errorf("detail/label: %q %q", c.Detail(), c.Label())
	}
	h := &ipCard{IP: "10.0.0.5", Nick: "Kiosk", Kind: "iot", Note: "lobby"}
	if h.Detail() != "iot · note: lobby" || h.Label() != "Kiosk (10.0.0.5)" {
		t.Errorf("host card: %q %q", h.Detail(), h.Label())
	}
	// render without a DB still works and falls back to the alert's own nickname column.
	d := &Dispatcher{Cfg: &config.Config{}, Now: time.Now}
	name := "tv"
	host := "10.0.0.9"
	m := d.render(context.Background(), []db.Alert{{Rule: "r", Severity: "warning", Host: &host, HostName: &name, Title: "something happened", Count: 2}})
	if !strings.Contains(m.Body, "[tv (10.0.0.9)]") || !strings.Contains(m.Body, "(x2)") {
		t.Errorf("fallback body: %q", m.Body)
	}
}

func TestMinSeverityOverride(t *testing.T) {
	var mu sync.Mutex
	deliveries := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); deliveries++; mu.Unlock() }))
	defer srv.Close()
	d := NewDispatcher(nil, &config.Config{NotifyWebhookURL: srv.URL, NotifyMinSeverity: "critical"}, srv.Client())
	if d.MinSeverity() != "critical" || d.Stats().MinSeverity != "critical" {
		t.Fatalf("default: %s", d.MinSeverity())
	}
	d.Notify(context.Background(), []db.Alert{{ID: 1, Rule: "r", Severity: "warning", Title: "w"}})
	mu.Lock()
	if deliveries != 0 {
		t.Fatal("warning must not be delivered at min=critical")
	}
	mu.Unlock()
	if err := d.SetMinSeverity(context.Background(), "Warning "); err != nil {
		t.Fatal(err)
	}
	if err := d.SetMinSeverity(context.Background(), "urgent"); err == nil {
		t.Fatal("bogus severity accepted")
	}
	if d.MinSeverity() != "warning" || d.Stats().MinSeverity != "warning" {
		t.Fatalf("override: %s", d.MinSeverity())
	}
	d.Notify(context.Background(), []db.Alert{{ID: 2, Rule: "r", Severity: "warning", Title: "w"}})
	mu.Lock()
	defer mu.Unlock()
	if deliveries != 1 {
		t.Fatalf("expected delivery after lowering the threshold, got %d", deliveries)
	}
}
