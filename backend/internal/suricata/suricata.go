// Package suricata ingests Suricata EVE JSON events delivered over syslog (UDP or TCP).
package suricata

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// AlertSink receives findings derived from IDS alerts (the rules engine's alert store).
type AlertSink interface {
	RaiseIDS(ctx context.Context, f db.Finding) error
}

// Listener receives EVE events.
type Listener struct {
	DB      *db.DB
	Addr    string
	Sink    AlertSink
	IsLocal func(netip.Addr) bool
	Now     func() time.Time

	received  atomic.Int64
	alerts    atomic.Int64
	names     atomic.Int64
	dropped   atomic.Int64
	malformed atomic.Int64
	ignored   atomic.Int64
	mu        sync.Mutex
	started   time.Time
	lastAt    time.Time
	lastErr   string
	lastErrAt time.Time
	types     map[string]*typeStat
}

type typeStat struct {
	count int64
	last  time.Time
}

// maxTypes bounds the per-type table so a misbehaving sender cannot grow it without limit;
// anything beyond is folded into "other".
const maxTypes = 24

// TypeStat is the per-event-type ingest counter shown on the IDS page.
type TypeStat struct {
	Type  string    `json:"type"`
	Count int64     `json:"count"`
	Last  time.Time `json:"last"`
	Used  string    `json:"used,omitempty"` // "alerts" (stored + raised), "names" (teaches hostnames) or "" (ignored)
}

// Stats is a snapshot for the API.
type Stats struct {
	Listen      string     `json:"listen"`
	Started     *time.Time `json:"started,omitempty"`
	Received    int64      `json:"received"`
	Alerts      int64      `json:"alerts"`
	Names       int64      `json:"names"`
	Dropped     int64      `json:"dropped"`
	Malformed   int64      `json:"malformed"` // lines that looked like JSON but would not parse (usually syslog truncation)
	Ignored     int64      `json:"ignored"`   // syslog lines with no JSON at all (other daemons forwarded alongside Suricata)
	LastEvent   *time.Time `json:"last_event,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
	Types       []TypeStat `json:"types"`
}

// Stats returns counters.
func (l *Listener) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := Stats{Listen: l.Addr, Received: l.received.Load(), Alerts: l.alerts.Load(), Names: l.names.Load(),
		Dropped: l.dropped.Load(), Malformed: l.malformed.Load(), Ignored: l.ignored.Load(), LastError: l.lastErr, Types: []TypeStat{}}
	if !l.started.IsZero() {
		t := l.started
		s.Started = &t
	}
	if !l.lastAt.IsZero() {
		t := l.lastAt
		s.LastEvent = &t
	}
	if !l.lastErrAt.IsZero() {
		t := l.lastErrAt
		s.LastErrorAt = &t
	}
	for k, v := range l.types {
		s.Types = append(s.Types, TypeStat{Type: k, Count: v.count, Last: v.last, Used: usedFor(k)})
	}
	sort.Slice(s.Types, func(i, j int) bool {
		if s.Types[i].Count != s.Types[j].Count {
			return s.Types[i].Count > s.Types[j].Count
		}
		return s.Types[i].Type < s.Types[j].Type
	})
	return s
}

// usedFor says what the analyzer does with an event type (mirrors handle).
func usedFor(t string) string {
	switch t {
	case "alert":
		return "alerts"
	case "dns.answer", "tls", "http":
		return "names"
	}
	return ""
}

// typeKey classifies an event for the ingest table. DNS is split because only answers carry
// names; queries are usually the bulk of what Suricata logs and are ignored.
func typeKey(ev *Event) string {
	if ev.EventType == "dns" {
		if ev.DNS != nil && (ev.DNS.Type == "answer" || len(ev.DNS.Answers) > 0 || len(ev.DNS.Grouped) > 0 || ev.DNS.RData != "") {
			return "dns.answer"
		}
		return "dns.query"
	}
	return ev.EventType
}

// note records one received event of the given type.
func (l *Listener) note(key string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastAt = at
	if l.types == nil {
		l.types = map[string]*typeStat{}
	}
	ts := l.types[key]
	if ts == nil {
		if len(l.types) >= maxTypes {
			key = "other"
			ts = l.types[key]
		}
		if ts == nil {
			ts = &typeStat{}
			l.types[key] = ts
		}
	}
	ts.count++
	ts.last = at
}

// Run listens on UDP and TCP until ctx is done.
func (l *Listener) Run(ctx context.Context) error {
	if l.Now == nil {
		l.Now = time.Now
	}
	l.mu.Lock()
	l.started = l.Now()
	l.mu.Unlock()
	pc, err := net.ListenPacket("udp", l.Addr)
	if err != nil {
		return fmt.Errorf("suricata udp listen: %w", err)
	}
	ln, err := net.Listen("tcp", l.Addr)
	if err != nil {
		pc.Close()
		return fmt.Errorf("suricata tcp listen: %w", err)
	}
	slog.Info("suricata listener started", "addr", l.Addr)
	go func() {
		<-ctx.Done()
		pc.Close()
		ln.Close()
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			l.HandleLine(ctx, string(buf[:n]))
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			sc := bufio.NewScanner(c)
			sc.Buffer(make([]byte, 1<<20), 1<<20)
			for sc.Scan() {
				l.HandleLine(ctx, sc.Text())
			}
		}(conn)
	}
}

// ExtractJSON returns the JSON object embedded in a syslog line (or the line itself).
func ExtractJSON(line string) (string, bool) {
	i := strings.Index(line, "{")
	j := strings.LastIndex(line, "}")
	if i < 0 || j <= i {
		return "", false
	}
	return line[i : j+1], true
}

// Event is the subset of EVE we use.
type Event struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	AppProto  string `json:"app_proto"`
	Alert     *struct {
		Action      string `json:"action"`
		SignatureID int64  `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
	DNS *struct {
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
	} `json:"dns"`
	TLS *struct {
		SNI string `json:"sni"`
	} `json:"tls"`
	HTTP *struct {
		Hostname string `json:"hostname"`
	} `json:"http"`
}

func (l *Listener) markMalformed(msg string) {
	l.malformed.Add(1)
	l.mu.Lock()
	l.lastErr = msg
	l.lastErrAt = l.Now()
	l.mu.Unlock()
}

// HandleLine parses one syslog/EVE line and stores what it carries.
func (l *Listener) HandleLine(ctx context.Context, line string) {
	js, ok := ExtractJSON(line)
	if !ok {
		// A line that opens an EVE record ('{"…') but has no matching close is a truncated
		// record — almost always the remote syslog transport cutting a long line. Count it so
		// the operator can see it (a plain syslog line with no '{' is just ignored).
		if i := strings.Index(line, "{"); i >= 0 && strings.HasPrefix(strings.TrimSpace(line[i:]), `{"`) {
			l.markMalformed("truncated event (no closing brace)")
		} else {
			l.ignored.Add(1) // e.g. filterlog/dhcpd lines when pfSense forwards "Everything"
		}
		return
	}
	var ev Event
	if err := json.Unmarshal([]byte(js), &ev); err != nil {
		l.markMalformed("malformed/truncated event (" + err.Error() + ")")
		return
	}
	if ev.EventType == "" {
		return
	}
	l.received.Add(1)
	l.note(typeKey(&ev), l.Now())
	if err := l.handle(ctx, &ev, js); err != nil {
		l.dropped.Add(1)
		l.mu.Lock()
		l.lastErr = err.Error()
		l.lastErrAt = l.Now()
		l.mu.Unlock()
		slog.Warn("suricata event", "type", ev.EventType, "err", err)
	}
}

func parseTS(s string, now time.Time) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05.999999-0700", time.RFC3339Nano, "2006-01-02T15:04:05.999999Z07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return now
}

func (l *Listener) handle(ctx context.Context, ev *Event, raw string) error {
	switch ev.EventType {
	case "alert":
		if ev.Alert == nil {
			return nil
		}
		ts := parseTS(ev.Timestamp, l.Now())
		e := &db.IDSEvent{TS: ts, Raw: json.RawMessage(raw)}
		if ev.SrcIP != "" {
			e.SrcIP = &ev.SrcIP
			e.SrcPort = &ev.SrcPort
		}
		if ev.DestIP != "" {
			e.DstIP = &ev.DestIP
			e.DstPort = &ev.DestPort
		}
		if ev.Proto != "" {
			p := strings.ToLower(ev.Proto)
			e.Proto = &p
		}
		if ev.AppProto != "" {
			e.AppProto = &ev.AppProto
		}
		sid, sig, cat, sev, act := ev.Alert.SignatureID, ev.Alert.Signature, ev.Alert.Category, ev.Alert.Severity, ev.Alert.Action
		e.SID, e.Signature, e.Category, e.Severity, e.Action = &sid, &sig, &cat, &sev, &act
		id, err := l.DB.InsertIDSEvent(ctx, e)
		if err != nil {
			return err
		}
		l.alerts.Add(1)
		if l.Sink != nil {
			f := l.finding(ev)
			f.Details["ids_event_id"] = id // lets the alert link back to the exact stored event
			return l.Sink.RaiseIDS(ctx, f)
		}
		return nil
	case "dns":
		if ev.DNS == nil {
			return nil
		}
		if ev.DNS.Type != "answer" && len(ev.DNS.Answers) == 0 && len(ev.DNS.Grouped) == 0 && ev.DNS.RData == "" {
			return nil
		}
		name := ev.DNS.RRName
		add := func(ip string) error {
			if _, err := netip.ParseAddr(ip); err != nil || name == "" {
				return nil
			}
			l.names.Add(1)
			return l.DB.UpsertIPName(ctx, ip, name, "dns")
		}
		for _, a := range ev.DNS.Answers {
			if a.RRType == "A" || a.RRType == "AAAA" {
				if a.RRName != "" {
					name = a.RRName
				}
				if err := add(a.RData); err != nil {
					return err
				}
			}
		}
		for _, t := range []string{"A", "AAAA"} {
			for _, ip := range ev.DNS.Grouped[t] {
				if err := add(ip); err != nil {
					return err
				}
			}
		}
		if (ev.DNS.RRType == "A" || ev.DNS.RRType == "AAAA") && ev.DNS.RData != "" {
			if err := add(ev.DNS.RData); err != nil {
				return err
			}
		}
		return nil
	case "tls":
		if ev.TLS != nil && ev.TLS.SNI != "" && ev.DestIP != "" {
			l.names.Add(1)
			return l.DB.UpsertIPName(ctx, ev.DestIP, ev.TLS.SNI, "tls")
		}
	case "http":
		if ev.HTTP != nil && ev.HTTP.Hostname != "" && ev.DestIP != "" {
			if _, err := netip.ParseAddr(ev.HTTP.Hostname); err == nil {
				return nil // Host header was an IP
			}
			l.names.Add(1)
			return l.DB.UpsertIPName(ctx, ev.DestIP, ev.HTTP.Hostname, "http")
		}
	}
	return nil
}

// finding maps an EVE alert to an analyzer finding. Suricata severity 1 = high.
func (l *Listener) finding(ev *Event) db.Finding {
	sev := db.SevInfo
	switch ev.Alert.Severity {
	case 1:
		sev = db.SevCritical
	case 2:
		sev = db.SevWarning
	}
	src, dst := ev.SrcIP, ev.DestIP
	host, peer := src, dst
	if l.IsLocal != nil {
		sa, errS := netip.ParseAddr(src)
		da, errD := netip.ParseAddr(dst)
		if errS == nil && errD == nil && !l.IsLocal(sa) && l.IsLocal(da) {
			host, peer = dst, src
		}
	}
	return db.Finding{Rule: "ids", Severity: sev, Host: host, Peer: peer, Key: fmt.Sprint(ev.Alert.SignatureID),
		Title: fmt.Sprintf("%s (%s → %s:%d)", ev.Alert.Signature, src, dst, ev.DestPort),
		Details: map[string]any{"sid": ev.Alert.SignatureID, "category": ev.Alert.Category, "suricata_severity": ev.Alert.Severity,
			"action": ev.Alert.Action, "src": src, "src_port": ev.SrcPort, "dst": dst, "dst_port": ev.DestPort, "proto": ev.Proto, "app_proto": ev.AppProto}}
}
