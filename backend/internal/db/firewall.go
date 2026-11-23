package db

import (
	"context"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
)

// FirewallEvent is one pfSense filterlog record.
type FirewallEvent struct {
	TS        time.Time
	Action    string
	Direction string
	Iface     string
	Reason    string
	RuleNum   *int32
	SubRule   string
	Anchor    string
	Tracker   *int64
	IPVersion int16
	Proto     *int16
	ProtoName string
	Src       netip.Addr
	SrcPort   *int32
	Dst       netip.Addr
	DstPort   *int32
	Length    *int32
	TTL       *int16
	TCPFlags  string
	ICMPType  string
}

var fwEventCols = []string{"ts", "action", "direction", "iface", "reason", "rule_num", "sub_rule", "anchor", "tracker",
	"ip_version", "proto", "proto_name", "src_ip", "src_port", "dst_ip", "dst_port", "length", "ttl", "tcp_flags", "icmp_type"}

// InsertFirewallEvents bulk-loads a batch with COPY.
func (d *DB) InsertFirewallEvents(ctx context.Context, evs []FirewallEvent) (int64, error) {
	if len(evs) == 0 {
		return 0, nil
	}
	return d.Pool.CopyFrom(ctx, pgx.Identifier{"fw_events"}, fwEventCols, pgx.CopyFromSlice(len(evs), func(i int) ([]any, error) {
		e := &evs[i]
		return []any{e.TS, e.Action, fwStr(e.Direction), fwStr(e.Iface), fwStr(e.Reason), e.RuleNum, fwStr(e.SubRule),
			fwStr(e.Anchor), e.Tracker, e.IPVersion, e.Proto, fwStr(e.ProtoName), fwAddr(e.Src), e.SrcPort,
			fwAddr(e.Dst), e.DstPort, e.Length, e.TTL, fwStr(e.TCPFlags), fwStr(e.ICMPType)}, nil
	}))
}

// PruneFirewallEvents deletes records older than keep and returns how many went.
func (d *DB) PruneFirewallEvents(ctx context.Context, keep time.Duration) (int64, error) {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM fw_events WHERE ts < now() - $1::interval`, keep.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func fwStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func fwAddr(a netip.Addr) *netip.Addr {
	if !a.IsValid() {
		return nil
	}
	return &a
}
