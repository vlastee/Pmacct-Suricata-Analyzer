package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
