package suricata

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

func TestExtractJSON(t *testing.T) {
	js, ok := ExtractJSON(`<134>Aug 27 12:00:00 pfsense suricata[123]: {"event_type":"alert","x":1}`)
	if !ok || js != `{"event_type":"alert","x":1}` {
		t.Errorf("extract: %q %v", js, ok)
	}
	if _, ok := ExtractJSON("no json here"); ok {
		t.Error("should not extract from plain text")
	}
}

func TestMalformedCounter(t *testing.T) {
	l := &Listener{Now: time.Now}
	// A syslog line carrying a truncated EVE record (valid-looking prefix, cut mid-JSON).
	l.HandleLine(context.Background(), `<134>Aug 27 12:00:00 pfsense suricata: {"event_type":"alert","src_ip":"1.2.3.`)
	if s := l.Stats(); s.Malformed != 1 || s.Received != 0 {
		t.Errorf("expected 1 malformed / 0 received, got %+v", s)
	}
	// A line with no JSON at all is ignored, not counted as malformed.
	l.HandleLine(context.Background(), "plain syslog line, no json")
	if s := l.Stats(); s.Malformed != 1 {
		t.Errorf("non-JSON line should not count as malformed: %+v", s)
	}
}

func TestFindingDirection(t *testing.T) {
	l := &Listener{IsLocal: func(a netip.Addr) bool { return a.As4()[0] == 10 }}
	ev := &Event{SrcIP: "8.8.8.8", DestIP: "10.0.0.5", DestPort: 443}
	ev.Alert = &struct {
		Action      string `json:"action"`
		SignatureID int64  `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	}{Action: "allowed", SignatureID: 2001, Signature: "ET bad", Category: "trojan", Severity: 1}
	f := l.finding(ev)
	if f.Host != "10.0.0.5" || f.Peer != "8.8.8.8" || f.Severity != db.SevCritical || f.Key != "2001" {
		t.Errorf("finding: %+v", f)
	}
}
