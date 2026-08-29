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
