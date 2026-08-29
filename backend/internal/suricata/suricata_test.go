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

func TestIngestCounters(t *testing.T) {
	l := &Listener{Now: time.Now}
	ctx := context.Background()
	l.HandleLine(ctx, `<134>Aug 27 12:00:00 pfsense suricata[1]: {"event_type":"dns","dns":{"type":"query","rrname":"a.example"}}`)
	l.HandleLine(ctx, `{"event_type":"dns","dns":{"type":"query","rrname":"b.example"}}`)
	l.HandleLine(ctx, `{"event_type":"flow","src_ip":"10.0.0.1"}`)
	l.HandleLine(ctx, `<13>Aug 27 12:00:00 pfsense filterlog[1]: 5,,,1000000103,igb1,match,block,in,4`)
	s := l.Stats()
	if s.Received != 3 || s.Ignored != 1 || s.LastEvent == nil || s.Started != nil || s.LastErrorAt != nil {
		t.Fatalf("stats: %+v", s)
	}
	// Sorted by count desc; DNS queries are classified separately from answers and marked unused.
	if len(s.Types) != 2 || s.Types[0].Type != "dns.query" || s.Types[0].Count != 2 || s.Types[0].Used != "" || s.Types[1].Type != "flow" || s.Types[1].Count != 1 {
		t.Fatalf("types: %+v", s.Types)
	}
	if usedFor("alert") != "alerts" || usedFor("dns.answer") != "names" || usedFor("tls") != "names" || usedFor("stats") != "" {
		t.Error("usedFor mapping")
	}
	if typeKey(&Event{EventType: "dns", DNS: &struct {
		Type    string `json:"type"`
		RRName  string `json:"rrname"`
		RRType  string `json:"rrtype"`
		RData   string `json:"rdata"`
		Answers []struct {
			RRName string `json:"rrname"`
			RRType string `json:"rrtype"`
			RData  string `json:"rdata"`
		} `json:"answers"`
		Grouped map[string][]string `json:"grouped"`
	}{Type: "answer"}}) != "dns.answer" {
		t.Error("answer should classify as dns.answer")
	}
	// Truncated JSON is malformed (with a timestamp), not ignored.
	l.HandleLine(ctx, `<134>Aug 27 12:00:00 pfsense suricata[1]: {"event_type":"alert","src_ip":"1.2.3.`)
	if s := l.Stats(); s.Malformed != 1 || s.LastErrorAt == nil || s.LastError == "" {
		t.Fatalf("malformed stats: %+v", s)
	}
}
