package suricata

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCleanJSON(t *testing.T) {
	plain := `{"event_type":"dns","dns":{"rrname":"a.example"}}`
	if got := cleanJSON(plain); got != plain {
		t.Errorf("clean record changed: %q", got)
	}
	// A DNS name carrying a NUL (seen live: Postgres refused it with SQLSTATE 22021).
	got := cleanJSON(`{"event_type":"dns","dns":{"rrname":"a\u0000b.example","answers":[{"rdata":"x\u0000"}]},"n":12345678901234567890}`)
	if strings.Contains(got, `\u0000`) || strings.Contains(got, "\x00") {
		t.Fatalf("NUL survived: %q", got)
	}
	var ev Event
	if err := json.Unmarshal([]byte(got), &ev); err != nil || ev.DNS == nil || ev.DNS.RRName != "a�b.example" || ev.DNS.Answers[0].RData != "x�" {
		t.Errorf("cleaned record lost its shape: %q (%v)", got, err)
	}
	if !strings.Contains(got, "12345678901234567890") {
		t.Errorf("big numbers must survive the rewrite: %q", got)
	}
	if got := cleanJSON("{\"a\":\"\xff\"}"); got != "{\"a\":\"�\"}" {
		t.Errorf("invalid UTF-8: %q", got)
	}
}

func TestOfferCountsOverflow(t *testing.T) {
	l := &Listener{Now: time.Now, lines: make(chan string, 2)}
	for i := range 5 {
		l.offer(fmt.Sprint("line ", i))
	}
	s := l.Stats()
	if s.Overflow != 3 || s.Queued != 2 || s.QueueCap != 2 {
		t.Errorf("want overflow 3, queued 2/2, got %+v", s)
	}
}

// Lines sent over UDP and TCP reach the workers through the queue.
func TestRunHandlesQueuedLines(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &Listener{Addr: addr, Now: time.Now, Workers: 2, QueueSize: 100}
	go func() { _ = l.Run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	var uc, tc net.Conn
	for time.Now().Before(deadline) {
		if tc, err = net.Dial("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if tc == nil {
		t.Fatalf("listener did not start: %v", err)
	}
	defer tc.Close()
	if uc, err = net.Dial("udp", addr); err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	for range 10 {
		_, _ = uc.Write([]byte("<13>Nov 23 10:00:00 pfsense filterlog[1]: 5,,,1000000103,vtnet0,match,block,in,4"))
	}
	_, _ = tc.Write([]byte(strings.Repeat("plain tcp line\n", 5)))
	for time.Now().Before(deadline) {
		if l.Stats().Ignored == 15 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("want 15 lines handled, stats %+v", l.Stats())
}

type claimFilterlog struct{ n int }

func (c *claimFilterlog) Handle(line string) bool {
	if strings.Contains(line, " filterlog ") {
		c.n++
		return true
	}
	return false
}

// Firewall log lines go to the firewall writer; everything else still reaches the EVE path.
func TestFirewallLinesAreRouted(t *testing.T) {
	fw := &claimFilterlog{}
	l := &Listener{Now: time.Now, Firewall: fw}
	l.HandleLine(context.Background(), `<134>1 2026-11-23T15:06:09-05:00 pfSense filterlog 1 - - 1,6,,1000000103,vtnet1,match,block,in,4`)
	l.HandleLine(context.Background(), `<30>1 2026-11-23T15:06:09-05:00 pfSense dhcp6c 1 - - Sending Solicit`)
	if s := l.Stats(); fw.n != 1 || s.Ignored != 1 {
		t.Errorf("routed %d to firewall, ignored %d", fw.n, s.Ignored)
	}
}
