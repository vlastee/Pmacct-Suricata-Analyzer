package firewall

import (
	"testing"
	"time"
)

var now = time.Date(2026, 11, 23, 20, 0, 0, 0, time.UTC)

func TestParseRFC5424TCP(t *testing.T) {
	// Shape copied from a live pfSense 2.8 line; addresses replaced with documentation ranges.
	line := `<134>1 2026-11-23T15:06:09.738698-05:00 pfSense.home.arpa filterlog 33866 - - 1,6,,1000000103,vtnet0,match,block,in,4,0x0,,112,5523,0,DF,6,tcp,52,198.51.100.7,203.0.113.10,63870,7680,0,S,2315636207,,65535,,mss;nop;wscale;nop;nop;sackOK`
	if !IsFilterlog(line) {
		t.Fatal("not recognised as filterlog")
	}
	e, ok := ParseLine(line, now)
	if !ok {
		t.Fatal("parse failed")
	}
	if !e.TS.Equal(time.Date(2026, 11, 23, 20, 6, 9, 738698000, time.UTC)) || e.TS.Location() != time.UTC {
		t.Errorf("ts %v", e.TS)
	}
	if e.Action != "block" || e.Direction != "in" || e.Iface != "vtnet0" || e.Reason != "match" || *e.RuleNum != 1 || e.SubRule != "6" || *e.Tracker != 1000000103 {
		t.Errorf("header %+v", e)
	}
	if e.IPVersion != 4 || *e.Proto != 6 || e.ProtoName != "tcp" || *e.Length != 52 || *e.TTL != 112 {
		t.Errorf("ip %+v", e)
	}
	if e.Src.String() != "198.51.100.7" || e.Dst.String() != "203.0.113.10" || *e.SrcPort != 63870 || *e.DstPort != 7680 || e.TCPFlags != "S" {
		t.Errorf("l4 %+v", e)
	}
}

func TestParseOtherProtocols(t *testing.T) {
	udp, ok := ParseCSV(`5,,,1000000103,igb1,match,block,in,4,0x0,,64,0,0,DF,17,udp,76,192.0.2.5,198.51.100.53,51234,53,56`, now)
	if !ok || udp.ProtoName != "udp" || *udp.SrcPort != 51234 || *udp.DstPort != 53 || udp.TCPFlags != "" {
		t.Errorf("udp %+v", udp)
	}
	igmp, ok := ParseCSV(`1,63,,11005,vtnet0,match,block,in,4,0x0,,1,11946,0,none,2,igmp,36,0.0.0.0,224.0.0.1,datalength=12 `, now)
	if !ok || igmp.ProtoName != "igmp" || igmp.Dst.String() != "224.0.0.1" || igmp.SrcPort != nil || *igmp.Tracker != 11005 {
		t.Errorf("igmp %+v", igmp)
	}
	icmp, ok := ParseCSV(`7,,,1700000000,igb0,match,pass,out,4,0x0,,64,1,0,none,1,icmp,84,192.0.2.1,198.51.100.1,request,1234,1`, now)
	if !ok || icmp.Action != "pass" || icmp.Direction != "out" || icmp.ICMPType != "request" {
		t.Errorf("icmp %+v", icmp)
	}
	v6, ok := ParseCSV(`9,,,1000000104,igb0,match,block,in,6,0x00,0x00000,64,tcp,6,80,2001:db8::1,2001:db8::2,40000,22,0,S,1,,64800,,mss`, now)
	if !ok || v6.IPVersion != 6 || v6.ProtoName != "tcp" || *v6.Proto != 6 || *v6.Length != 80 || *v6.TTL != 64 ||
		v6.Src.String() != "2001:db8::1" || *v6.DstPort != 22 || v6.TCPFlags != "S" {
		t.Errorf("v6 %+v", v6)
	}
	if !udp.TS.Equal(now) {
		t.Errorf("CSV without a timestamp should use now: %v", udp.TS)
	}
}

func TestParseRFC3164AndJunk(t *testing.T) {
	e, ok := ParseLine(`<134>Nov 23 15:06:09 filterlog[33866]: 5,,,1000000103,igb1,match,block,in,4,0x0,,64,0,0,DF,17,udp,76,192.0.2.5,198.51.100.53,51234,53,56`, now)
	if !ok || e.Iface != "igb1" || !e.TS.Equal(now) {
		t.Errorf("bsd syslog: %v %+v", ok, e)
	}
	for _, bad := range []string{
		`<134>1 2026-11-23T15:06:09-05:00 pfSense filterlog 1 - - garbage`,
		`<134>1 2026-11-23T15:06:09-05:00 pfSense filterlog 1 - - 1,,,2,igb1,match,,in,4`, // no action
		`<134>1 2026-11-23T15:06:09-05:00 pfSense suricata 1 - - {"event_type":"dns"}`,
	} {
		if _, ok := ParseLine(bad, now); ok {
			t.Errorf("accepted junk: %q", bad)
		}
	}
	// Header-only records (unknown IP version) are still kept.
	if e, ok := ParseCSV(`1,,,2,igb1,match,block,in,9`, now); !ok || e.IPVersion != 0 || e.Action != "block" {
		t.Errorf("header only: %v %+v", ok, e)
	}
}
