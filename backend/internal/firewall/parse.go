// Package firewall ingests the pfSense firewall log (filterlog) forwarded over syslog and
// stores it in fw_events.
package firewall

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// Syslog framings pfSense uses: RFC 5424 (current default) and the older BSD format.
var (
	rfc5424 = regexp.MustCompile(`^<\d+>1 (\S+) \S+ filterlog \S+ \S+ (?:-|\[.*?\]) ?(.*)$`)
	rfc3164 = regexp.MustCompile(`^<\d+>(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d )?(?:\S+ )?filterlog(?:\[\d+\])?: ?(.*)$`)
)

// IsFilterlog reports whether a syslog line came from filterlog (cheap pre-check).
func IsFilterlog(line string) bool { return strings.Contains(line, " filterlog") }

// ParseLine extracts the record from one syslog line. now is used when the line carries no
// usable timestamp (BSD syslog has no year or zone).
func ParseLine(line string, now time.Time) (db.FirewallEvent, bool) {
	line = strings.TrimRight(line, "\r\n\x00")
	ts, csv := now, ""
	if m := rfc5424.FindStringSubmatch(line); m != nil {
		if t, err := time.Parse(time.RFC3339Nano, m[1]); err == nil {
			ts = t
		}
		csv = m[2]
	} else if m := rfc3164.FindStringSubmatch(line); m != nil {
		csv = m[1]
	} else {
		return db.FirewallEvent{}, false
	}
	return ParseCSV(csv, ts)
}

// ParseCSV decodes the filterlog CSV body (pfSense "Filter Log Format"):
//
//	rule,sub-rule,anchor,tracker,iface,reason,action,dir,ipver,<ip fields>,<proto fields>
//
// IPv4: tos,ecn,ttl,id,offset,flags,proto-id,proto-text,length,src,dst
// IPv6: class,flow-label,hop-limit,proto-text,proto-id,length,src,dst
// TCP:  sport,dport,data-len,flags,seq,ack,window,urg,options   UDP: sport,dport,data-len
// ICMP: type,…
func ParseCSV(csv string, ts time.Time) (db.FirewallEvent, bool) {
	f := strings.Split(strings.TrimSpace(csv), ",")
	if len(f) < 9 {
		return db.FirewallEvent{}, false
	}
	e := db.FirewallEvent{TS: ts.UTC(), RuleNum: i32(f[0]), SubRule: f[1], Anchor: f[2], Tracker: i64(f[3]),
		Iface: f[4], Reason: f[5], Action: f[6], Direction: f[7]}
	if e.Action == "" {
		return db.FirewallEvent{}, false
	}
	var rest []string
	switch f[8] {
	case "4":
		e.IPVersion = 4
		if len(f) < 20 {
			return e, true // header only: still worth keeping (action/iface/rule)
		}
		e.TTL, e.Proto, e.ProtoName, e.Length = i16(f[11]), i16(f[15]), strings.ToLower(f[16]), i32(f[17])
		e.Src, _ = netip.ParseAddr(f[18])
		e.Dst, _ = netip.ParseAddr(f[19])
		rest = f[20:]
	case "6":
		e.IPVersion = 6
		if len(f) < 17 {
			return e, true
		}
		e.TTL, e.ProtoName, e.Proto, e.Length = i16(f[11]), strings.ToLower(f[12]), i16(f[13]), i32(f[14])
		e.Src, _ = netip.ParseAddr(f[15])
		e.Dst, _ = netip.ParseAddr(f[16])
		rest = f[17:]
	default:
		return e, true
	}
	switch e.ProtoName {
	case "tcp":
		if len(rest) >= 2 {
			e.SrcPort, e.DstPort = i32(rest[0]), i32(rest[1])
		}
		if len(rest) >= 4 {
			e.TCPFlags = rest[3]
		}
	case "udp":
		if len(rest) >= 2 {
			e.SrcPort, e.DstPort = i32(rest[0]), i32(rest[1])
		}
	case "icmp", "ipv6-icmp":
		if len(rest) >= 1 {
			e.ICMPType = rest[0]
		}
	}
	return e, true
}

func i64(s string) *int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func i32(s string) *int32 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return nil
	}
	v := int32(n)
	return &v
}

func i16(s string) *int16 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return nil
	}
	v := int16(n)
	return &v
}
