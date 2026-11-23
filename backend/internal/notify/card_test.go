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

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

func sp(s string) *string { return &s }
func ip(n int) *int       { return &n }

// A blocked C2 callback: the card must name machine, program, traffic proof, outcome, names,
// verdict sources with engines, and pivots.
func oneWayCtx() *alertCtx {
	t0 := time.Date(2026, 11, 22, 20, 1, 0, 0, time.UTC)
	t1 := t0.Add(13 * time.Minute)
	seen := t1.Add(-time.Minute)
	return &alertCtx{
		Alert: db.Alert{ID: 3712, Rule: "one_way", Severity: db.SevCritical, Host: sp("10.0.0.120"), Peer: sp("82.147.206.13"),
			Title: "10.0.0.120 sent 14 packets to flagged 82.147.206.13 in 7 flows and got nothing back (blocked or unanswered) (rep:abuseipdb)",
			Count: 2, FirstSeen: t0.Add(4 * time.Minute), LastSeen: t1},
		Window: db.Window{Since: t0.Add(-11 * time.Minute), Until: t1.Add(2 * time.Minute)},
		Host:   &ipCard{IP: "10.0.0.120", Nick: "DSV Laptop", Kind: "pc"},
		Peer:   &ipCard{IP: "82.147.206.13", Org: "Etihad Etisalat", Geo: "SA, Riyadh", Flags: []string{"hosting"}},
		Agent:  &db.Agent{ID: 4, Name: "dsv-laptop", Hostname: "DSV-LT-0142", OS: "windows", Arch: "amd64", LastSeen: &seen},
		Procs: []db.EndpointProcess{{AgentID: 4, Name: "updater.exe", Exe: `C:\Users\jdoe\AppData\Local\Temp\updater.exe`, User: `CORP\jdoe`,
			PID: 4412, PIDs: 1, Cmdline: `updater.exe -k --silent`, SHA256: strings.Repeat("ab", 32), Conns: 7, Ports: []int32{443}}},
		Ident: map[string]*db.ProgramIdentity{`C:\Users\jdoe\AppData\Local\Temp\updater.exe`: {Signature: "unsigned", Origin: "tmp", Verified: nil}},
		Files: map[string]*db.FileIntel{strings.Repeat("ab", 32): {VT: db.FileVT{Status: "ok", Malicious: ip(41), Undetected: ip(30), Label: "trojan.agent"}}},
		Traffic: &db.PairTraffic{FlowsOut: 7, PacketsOut: 14, BytesOut: 840, First: &t0, Last: &t1,
			Services: []db.PairService{{Proto: 6, Port: 443, Flows: 7, Packets: 14, Bytes: 840}}},
		History:  &db.PairHistory{Flows: 7, Days: 1, First: &t0},
		HistDays: 7,
		Names:    []db.IPName{{Name: "evil.sslip.io", Source: "dns", Hits: 3, LastSeen: t0}},
		PeerInfo: &db.IPInfo{IP: "82.147.206.13", ASN: sp("AS35819"),
			VT: &db.VTResult{Status: "ok", Malicious: ip(5), Suspicious: ip(1), Harmless: ip(60), Undetected: ip(26), LastAnalysis: &t0}},
		VTDets: []db.VTDetection{{Engine: "Fortinet", Category: "malicious", Result: "malware"}, {Engine: "Kaspersky", Category: "malicious", Result: "malicious"},
			{Engine: "Sophos", Category: "suspicious", Result: "suspicious"}},
		VTDetsOK: true,
		Reps:     []db.Reputation{{Source: "abuseipdb", Status: "ok", Flagged: true, Score: ip(87), LookupAt: t0}},
		Lists:    []string{"feodo"},
		BaseURL:  "https://10.0.0.210:8091",
	}
}

func TestCardOneWay(t *testing.T) {
	c := oneWayCtx()
	out := c.render(c.Alert.LastSeen.Add(2 * time.Minute))
	for _, want := range []string{
		"🚨 CRITICAL · one_way · alert #3712",
		"DSV Laptop (10.0.0.120) sent 14 packets",
		"Alert seen 2 times · first 2026-11-22 20:05 UTC · last 2026-11-22 20:14 UTC",
		"DSV Laptop (10.0.0.120) · pc",
		"agent dsv-laptop · hostname DSV-LT-0142 · windows amd64 · last report 3 min ago",
		`User(s): CORP\jdoe`,
		`updater.exe · pid 4412 · user CORP\jdoe`,
		`Path: C:\Users\jdoe\AppData\Local\Temp\updater.exe`,
		"Cmd: updater.exe -k --silent",
		"7 connections to this peer · port 443",
		"signature unsigned · origin tmp",
		"file on VirusTotal: 41/71 malicious (trojan.agent)",
		"2026-11-22 20:01–20:14 UTC (13 min)",
		"→ TCP/443 (https) ×7",
		"Out 14 pkts / 840 B in 7 flows · In 0 pkts / 0 B in 0 flows",
		"Pair history (7d): 7 flow records on 1 day",
		"One-way only: 14 packets sent, 0 received.",
		"pfSense either dropped them or the peer never answered",
		"~2.0 packets per flow fits connection attempts (SYN retries) only",
		"evil.sslip.io · DNS answer · 3 hits",
		"🏷️ Verdict (flag is on the IP 82.147.206.13)",
		"VirusTotal: 5 malicious, 1 suspicious of 92 engines · analysed 2026-11-22",
		"Engines: Fortinet (malware), Kaspersky (malicious), Sophos (suspicious)",
		"https://www.virustotal.com/gui/ip-address/82.147.206.13",
		"AbuseIPDB: FLAGGED, confidence 87% · https://www.abuseipdb.com/check/82.147.206.13 · checked 2026-11-22",
		"Threat lists: feodo",
		"Network: Etihad Etisalat · SA, Riyadh · AS35819 · hosting",
		"Alert #3712: https://10.0.0.210:8091/#/alerts?host=10.0.0.120",
		"Raw flows: https://10.0.0.210:8091/#/flows?ip=82.147.206.13&port=443&since=2026-11-22T19%3A50%3A00Z&until=2026-11-22T20%3A16%3A00Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("card missing %q\n---\n%s", want, out)
		}
	}
	if n := len([]rune(out)); n > maxCardChars+1 {
		t.Errorf("card too long: %d", n)
	}
}

func TestCardOutcomes(t *testing.T) {
	c := oneWayCtx()
	c.Traffic.FlowsIn, c.Traffic.PacketsIn = 6, 40
	if got := c.outcome(); !strings.HasPrefix(got, "Two-way:") || !strings.Contains(got, "40 packets back") {
		t.Errorf("two-way: %q", got)
	}
	c.IDSEvent = &db.IDSEvent{ID: 9, Action: sp("allowed")}
	if got := c.outcome(); !strings.Contains(got, `action "allowed"`) {
		t.Errorf("ids allowed: %q", got)
	}
	c.IDSEvent.Action = sp("blocked")
	if got := c.outcome(); !strings.HasPrefix(got, "Blocked by Suricata") {
		t.Errorf("ids blocked: %q", got)
	}
	c.IDSEvent, c.Traffic = nil, nil
	if got := c.outcome(); got != "" {
		t.Errorf("no data should say nothing, got %q", got)
	}
}

func TestCardWithoutAgentOrData(t *testing.T) {
	c := &alertCtx{Alert: db.Alert{ID: 5, Rule: "reputation", Severity: db.SevWarning, Host: sp("10.0.0.9"), Peer: sp("203.0.113.5"), Title: "x", Count: 1},
		Window: db.Window{Since: time.Unix(0, 0), Until: time.Unix(600, 0)}}
	out := c.render(time.Now())
	for _, want := range []string{"No endpoint agent on this address", "No flow records between 10.0.0.9 and 203.0.113.5", "No DNS answer, TLS SNI or HTTP Host seen"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "⚙️ Process") || strings.Contains(out, "🔗 Pivot") {
		t.Errorf("process/pivot sections need an agent / base URL:\n%s", out)
	}
	// VT counted but engine names not stored yet.
	c.PeerInfo = &db.IPInfo{VT: &db.VTResult{Status: "ok", Malicious: ip(3)}}
	if out := c.render(time.Now()); !strings.Contains(out, "names arrive with the next VirusTotal refresh") {
		t.Errorf("expected engine-name hint:\n%s", out)
	}
}

func TestCardIDSEvent(t *testing.T) {
	raw := json.RawMessage(`{"in_iface":"vtnet1","direction":"to_server","alert":{"rev":2}}`)
	sid := int64(2210044)
	c := oneWayCtx()
	c.IDSEvent = &db.IDSEvent{ID: 77, TS: time.Date(2026, 11, 22, 20, 3, 0, 0, time.UTC), SID: &sid, Signature: sp("ET MALWARE test"), Category: sp("A Network Trojan was Detected"),
		Severity: ip(1), Action: sp("allowed"), SrcIP: sp("10.0.0.120"), SrcPort: ip(50688), DstIP: sp("82.147.206.13"), DstPort: ip(443), Proto: sp("tcp"), AppProto: sp("tls"), Raw: raw}
	out := c.render(time.Now())
	for _, want := range []string{"sid 2210044 rev 2 · ET MALWARE test · A Network Trojan was Detected · sev 1 · action allowed",
		"10.0.0.120:50688 → 82.147.206.13:443 tcp/tls", "Sensor: vtnet1 · to_server", "IDS event: https://10.0.0.210:8091/#/ids?event=77"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
}

func TestTelegramChunks(t *testing.T) {
	big := strings.Repeat("line of text\n", 400) // ~5200 chars: must be split on a line break
	m := Message{Title: "[CRITICAL] 3 new alerts", Alerts: make([]db.Alert, 3), Parts: []string{"card one", big, "card three"}}
	chunks := telegramChunks(m)
	if len(chunks) < 2 {
		t.Fatalf("expected split, got %d chunk(s)", len(chunks))
	}
	if !strings.HasPrefix(chunks[0], "[CRITICAL] 3 new alerts\n\ncard one") {
		t.Errorf("first chunk should carry the batch title and first card: %q", chunks[0][:60])
	}
	total := 0
	for _, c := range chunks {
		if n := len([]rune(c)); n > telegramLimit {
			t.Errorf("chunk over limit: %d", n)
		}
		total += strings.Count(c, "line of text")
	}
	if total != 400 || !strings.Contains(chunks[len(chunks)-1], "card three") {
		t.Errorf("content lost: %d lines, last=%q", total, chunks[len(chunks)-1])
	}
	// A single alert is sent as its card alone (the card has its own header).
	if got := telegramChunks(Message{Title: "t", Alerts: make([]db.Alert, 1), Parts: []string{"only card"}}); len(got) != 1 || got[0] != "only card" {
		t.Errorf("single: %q", got)
	}
}

func TestTelegramSendsEveryChunk(t *testing.T) {
	var mu sync.Mutex
	var texts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		texts = append(texts, body["text"].(string))
		mu.Unlock()
	}))
	defer srv.Close()
	tg := &Telegram{Token: "T", ChatID: "-100", Client: srv.Client(), BaseURL: srv.URL}
	m := Message{Title: "x", Alerts: make([]db.Alert, 2), Parts: []string{strings.Repeat("a", 3900), strings.Repeat("b", 3900)}}
	if err := tg.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if len(texts) != 2 {
		t.Fatalf("want 2 messages, got %d", len(texts))
	}
}

// With the firewall log ingested, the outcome states pfSense's verdict instead of guessing.
func TestCardFirewallVerdict(t *testing.T) {
	c := oneWayCtx()
	tr := int64(1000000103)
	t0 := time.Date(2026, 11, 22, 20, 1, 0, 0, time.UTC)
	c.FirewallOn = true
	c.Firewall = []db.FirewallRuleHit{{Action: "block", Iface: "vtnet1", Direction: "in", Tracker: &tr, Label: "Default deny (IPv4)",
		Outbound: true, Packets: 14, Attempts: 14, First: t0, Last: t0.Add(13 * time.Minute), Flags: []string{"S"}, Ports: []int32{443}}}
	out := c.render(c.Alert.LastSeen.Add(time.Minute))
	for _, want := range []string{
		`One-way: 14 packets sent, 0 received. pfSense blocked 14 packets (14 new connection attempts) from 10.0.0.120 by "Default deny (IPv4)" (tracker 1000000103) on vtnet1, 2026-11-22 20:01–20:14 UTC (13 min), TCP flags S.`,
		"Firewall log: https://10.0.0.210:8091/#/firewall?ip=82.147.206.13&since=",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "no firewall-log feed") || strings.Contains(out, "inferred") {
		t.Errorf("guesswork left in a card that has the facts:\n%s", out)
	}
	// Ingested but nothing logged: say the peer most likely never answered.
	c.Firewall = nil
	if got := c.outcome(); !strings.Contains(got, "pfSense logged no block for this pair") {
		t.Errorf("no-block outcome: %q", got)
	}
	// Inbound blocks and passes are described when there are no flows at all.
	c.Traffic = nil
	c.Firewall = []db.FirewallRuleHit{{Action: "block", Outbound: false, Packets: 3}, {Action: "pass", Outbound: true, Packets: 2}}
	if got := c.outcome(); !strings.Contains(got, "pfSense blocked 3 packets coming from 82.147.206.13") || !strings.Contains(got, "2 packets as passed") {
		t.Errorf("inbound/pass outcome: %q", got)
	}
}
