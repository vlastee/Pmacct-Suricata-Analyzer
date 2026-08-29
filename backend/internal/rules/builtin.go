package rules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

func fmtBytes(n int64) string {
	f := float64(n)
	for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
		if f < 1024 || u == "TB" {
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return ""
}

func builtinRules() []*Rule {
	return []*Rule{
		{
			Name: "ids", Title: "Suricata IDS alert", Severity: db.SevWarning,
			Description: "Alerts received from Suricata (EVE over syslog). Suricata severity 1 maps to critical, 2 to warning, 3+ to info. Disable here to keep IDS events out of the alert list (they are still stored).",
			Interval:    365 * 24 * time.Hour, Window: time.Minute,
			Params: []Param{{"min_suricata_severity", "Ignore events with a Suricata severity number above this (1 = high, 3 = low)", 3}},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				return nil, nil
			},
		},
		{
			Name: "threat_feed", Title: "Traffic with threat-listed IP", Severity: db.SevCritical,
			Description: "A local host exchanged traffic with an address on a threat intelligence feed (botnet C2, Tor exit, spam/attack sources).",
			Interval:    time.Minute, Window: 10 * time.Minute,
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				hits, err := e.DB.DetectThreatListHits(ctx, w, e.Cfg.LocalNetworksCIDR())
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					dir := "bidirectional"
					if !h.HasIn {
						dir = "outbound only (unanswered)"
					} else if !h.HasOut {
						dir = "inbound only"
					}
					out = append(out, db.Finding{Host: h.Host, Peer: h.Peer,
						Title:   fmt.Sprintf("%s talked to %s (listed: %s)", h.Host, h.Peer, strings.Join(h.Lists, ", ")),
						Details: map[string]any{"lists": h.Lists, "bytes": h.Bytes, "flows": h.Flows, "direction": dir}})
				}
				return out, nil
			},
		},
		{
			Name: "reputation", Title: "Traffic with flagged IP", Severity: db.SevWarning,
			Description: "A local host exchanged traffic with an address flagged by VirusTotal (>= min_malicious engines), AbuseIPDB or GreyNoise. Escalates to critical when many engines agree.",
			Interval:    time.Minute, Window: 10 * time.Minute,
			Params: []Param{
				{"min_malicious", "VirusTotal engines reporting malicious before the peer counts as flagged", 2},
				{"critical_malicious", "Engines reporting malicious for critical severity", 5},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				hits, err := e.DB.DetectReputationHits(ctx, w, e.Cfg.LocalNetworksCIDR(), p.Int("min_malicious"))
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					f := db.Finding{Host: h.Host, Peer: h.Peer,
						Title: fmt.Sprintf("%s talked to flagged %s (%s)", h.Host, h.Peer, strings.Join(h.Sources, ", ")),
						Details: map[string]any{"sources": h.Sources, "vt_malicious": h.Malicious, "vt_suspicious": h.Suspicious, "bytes": h.Bytes,
							"flows": h.Flows, "country": h.CountryCode, "as_org": h.ASOrg, "inbound": h.HasIn, "outbound": h.HasOut}}
					if h.Malicious >= p.Int("critical_malicious") {
						f.Severity = db.SevCritical
					}
					out = append(out, f)
				}
				return out, nil
			},
		},
		{
			Name: "suspicious_port", Title: "Suspicious outbound service", Severity: db.SevWarning,
			Description: "A local host connected out to a service that is rarely legitimate from a LAN device: Telnet, SMB, RDP, SMTP, IRC, SOCKS, VNC. Mining pools and Tor ports are critical.",
			Interval:    time.Minute, Window: 10 * time.Minute,
			Params: []Param{
				{"ports", "Ports that raise a warning", []any{23, 445, 3389, 25, 6667, 1080, 5900, 135, 139}},
				{"critical_ports", "Ports that raise a critical alert (mining pools, Tor)", []any{3333, 4444, 14444, 5555, 7777, 9001, 9030, 9050}},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				warn, crit := p.Ints("ports"), p.Ints("critical_ports")
				critSet := map[int]bool{}
				for _, c := range crit {
					critSet[c] = true
				}
				uses, err := e.DB.DetectSuspiciousPorts(ctx, w, e.Cfg.LocalNetworksCIDR(), append(warn, crit...))
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, u := range uses {
					svc := db.ServiceName(u.Port)
					if svc == "" {
						svc = fmt.Sprint(u.Port)
					}
					f := db.Finding{Host: u.Host, Port: u.Port,
						Title:   fmt.Sprintf("%s connected out on %d/%s (%s) to %d peer(s), e.g. %s", u.Host, u.Port, db.ProtoName(u.Proto), svc, u.Peers, u.TopPeer),
						Details: map[string]any{"port": u.Port, "proto": db.ProtoName(u.Proto), "service": svc, "peers": u.Peers, "top_peer": u.TopPeer, "bytes": u.Bytes, "flows": u.Flows}}
					if critSet[u.Port] {
						f.Severity = db.SevCritical
					}
					out = append(out, f)
				}
				return out, nil
			},
		},
		{
			Name: "port_scan", Title: "Port scan", Severity: db.SevWarning,
			Description: "One source probed many distinct ports on a single target with tiny flows (SYN-only). Covers inbound recon on exposed services and infected devices probing the LAN.",
			Interval:    time.Minute, Window: 5 * time.Minute,
			Params: []Param{
				{"min_ports", "Distinct destination ports within the window", 20},
				{"max_avg_packets", "Average packets per flow at or below which flows count as probes", 3.0},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				hits, err := e.DB.DetectPortScans(ctx, w, e.Cfg.LocalNetworksCIDR(), p.Int("min_ports"), p.Float("max_avg_packets"))
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					host, peer := h.Src, h.Dst
					if !h.SrcLocal && h.DstLocal {
						host, peer = h.Dst, h.Src
					}
					out = append(out, db.Finding{Host: host, Peer: peer, Key: "scan:" + h.Src,
						Title:   fmt.Sprintf("%s scanned %d ports on %s", h.Src, h.Ports, h.Dst),
						Details: map[string]any{"scanner": h.Src, "target": h.Dst, "ports": h.Ports, "flows": h.Flows, "avg_packets": h.AvgPackets, "scanner_local": h.SrcLocal}})
				}
				return out, nil
			},
		},
		{
			Name: "host_scan", Title: "Host sweep", Severity: db.SevWarning,
			Description: "One source contacted many distinct hosts with tiny flows: network sweep, worm-like propagation, or a device whose outbound attempts are being blocked.",
			Interval:    time.Minute, Window: 5 * time.Minute,
			Params: []Param{
				{"min_hosts", "Distinct destination hosts within the window", 25},
				{"max_avg_packets", "Average packets per flow at or below which flows count as probes", 3.0},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				hits, err := e.DB.DetectHostScans(ctx, w, e.Cfg.LocalNetworksCIDR(), p.Int("min_hosts"), p.Float("max_avg_packets"))
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					f := db.Finding{Title: fmt.Sprintf("%s swept %d hosts (mostly port %d)", h.Src, h.Hosts, h.TopPort),
						Details: map[string]any{"scanner": h.Src, "hosts": h.Hosts, "flows": h.Flows, "avg_packets": h.AvgPackets, "top_port": h.TopPort, "scanner_local": h.SrcLocal}}
					if h.SrcLocal {
						f.Host = h.Src
					} else {
						f.Peer = h.Src
					}
					out = append(out, f)
				}
				return out, nil
			},
		},
		{
			Name: "brute_force", Title: "Brute force on exposed service", Severity: db.SevWarning,
			Description: "An external address opened many short connections to one local service (SSH/HTTPS/RDP port forward) within the window.",
			Interval:    time.Minute, Window: 5 * time.Minute,
			Params: []Param{
				{"min_flows", "Connections from one source to one local service within the window", 30},
				{"max_avg_bytes", "Average bytes per connection at or below which they count as attempts", 3000.0},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				hits, err := e.DB.DetectBruteForce(ctx, w, e.Cfg.LocalNetworksCIDR(), p.Int("min_flows"), p.Float("max_avg_bytes"))
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					svc := db.ServiceName(h.Port)
					out = append(out, db.Finding{Host: h.Dst, Peer: h.Src, Port: h.Port,
						Title:   fmt.Sprintf("%s hammered %s:%d/%s %s (%d connections)", h.Src, h.Dst, h.Port, db.ProtoName(h.Proto), svc, h.Flows),
						Details: map[string]any{"source": h.Src, "target": h.Dst, "port": h.Port, "service": svc, "flows": h.Flows, "avg_bytes": h.AvgBytes}})
				}
				return out, nil
			},
		},
		{
			Name: "one_way", Title: "Unanswered outbound connections", Severity: db.SevWarning,
			Description: "A local host sent traffic to many external peers that never replied within the window: blocked by the firewall, dead C2 infrastructure, or scanning. Unanswered attempts toward listed/flagged peers are critical.",
			Interval:    2 * time.Minute, Window: 15 * time.Minute,
			Params: []Param{
				{"min_peers", "Distinct unanswered external peers within the window", 10},
				{"min_malicious", "VirusTotal engines for a peer to count as flagged", 2},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				locals := e.Cfg.LocalNetworksCIDR()
				var out []db.Finding
				hits, err := e.DB.DetectOneWay(ctx, w, locals, p.Int("min_peers"))
				if err != nil {
					return nil, err
				}
				for _, h := range hits {
					out = append(out, db.Finding{Host: h.Host,
						Title:   fmt.Sprintf("%s has %d unanswered external peers (e.g. %s)", h.Host, h.Peers, strings.Join(h.Sample, ", ")),
						Details: map[string]any{"peers": h.Peers, "flows": h.Flows, "sample": h.Sample}})
				}
				flagged, err := e.DB.DetectOneWayFlagged(ctx, w, locals, p.Int("min_malicious"))
				if err != nil {
					return nil, err
				}
				for _, h := range flagged {
					out = append(out, db.Finding{Host: h.Host, Peer: h.Peer, Severity: db.SevCritical, Key: "flagged",
						Title:   fmt.Sprintf("%s tried to reach flagged %s with no reply (%s)", h.Host, h.Peer, strings.Join(h.Reasons, ", ")),
						Details: map[string]any{"reasons": h.Reasons, "flows": h.Flows, "hint": "unanswered attempts toward known-bad infrastructure often mean malware whose callbacks are being blocked"}})
				}
				return out, nil
			},
		},
		{
			Name: "dns_resolver", Title: "DNS bypassing the router", Severity: db.SevWarning,
			Description: "A local host sent DNS (53) or DNS-over-TLS (853) directly to an external resolver instead of the router. Configured gateways and allowed resolvers are ignored.",
			Interval:    2 * time.Minute, Window: 10 * time.Minute,
			Params: []Param{
				{"allowed_resolvers", "External resolvers that are fine (comma-separated IPs)", []any{}},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				uses, err := e.DB.DetectExternalDNS(ctx, w, e.Cfg.LocalNetworksCIDR(), e.gatewayList(), p.Strings("allowed_resolvers"))
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, u := range uses {
					out = append(out, db.Finding{Host: u.Host, Peer: u.Resolver, Port: u.Port,
						Title:   fmt.Sprintf("%s uses external DNS %s:%d (%d queries)", u.Host, u.Resolver, u.Port, u.Flows),
						Details: map[string]any{"resolver": u.Resolver, "port": u.Port, "flows": u.Flows, "bytes": u.Bytes}})
				}
				return out, nil
			},
		},
		{
			Name: "dns_volume", Title: "Excessive DNS", Severity: db.SevWarning,
			Description: "A local host generated an unusually large amount of DNS traffic: malware domain generation, DNS tunnelling, or a misbehaving app.",
			Interval:    5 * time.Minute, Window: time.Hour,
			Params: []Param{
				{"min_flows", "DNS flows within the window", 3000},
				{"min_bytes", "DNS bytes within the window", 5000000},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				hits, err := e.DB.DetectDNSVolume(ctx, w, e.Cfg.LocalNetworksCIDR(), e.gatewayList(), p.Int("min_flows"), int64(p.Int("min_bytes")))
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					out = append(out, db.Finding{Host: h.Host,
						Title:   fmt.Sprintf("%s made %d DNS flows (%s) in an hour", h.Host, h.Flows, fmtBytes(h.Bytes)),
						Details: map[string]any{"flows": h.Flows, "bytes": h.Bytes}})
				}
				return out, nil
			},
		},
		{
			Name: "geo_policy", Title: "Traffic with watched countries", Severity: db.SevWarning,
			Description: "A local host exchanged traffic with an address geolocated in a country on the watch list.",
			Interval:    2 * time.Minute, Window: 10 * time.Minute,
			Params: []Param{
				{"countries", "ISO country codes to watch (comma-separated); empty disables", []any{}},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				countries := p.Strings("countries")
				if len(countries) == 0 {
					return nil, nil
				}
				for i := range countries {
					countries[i] = strings.ToUpper(countries[i])
				}
				hits, err := e.DB.DetectGeo(ctx, w, e.Cfg.LocalNetworksCIDR(), countries)
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					c := h.CountryCode
					if h.Country != nil {
						c = *h.Country
					}
					out = append(out, db.Finding{Host: h.Host, Peer: h.Peer,
						Title:   fmt.Sprintf("%s talked to %s in %s", h.Host, h.Peer, c),
						Details: map[string]any{"country": h.CountryCode, "as_org": h.ASOrg, "bytes": h.Bytes, "flows": h.Flows}})
				}
				return out, nil
			},
		},
		{
			Name: "volume_anomaly", Title: "Outbound volume anomaly", Severity: db.SevWarning,
			Description: "A local host uploaded far more in the last full hour than its own baseline for that hour of day (median + factor x MAD over the lookback). Possible exfiltration or a device gone rogue.",
			Interval:    10 * time.Minute, Window: time.Hour,
			Params: []Param{
				{"factor", "How many MADs above the median counts as anomalous", 5.0},
				{"min_bytes", "Ignore hours below this many bytes out", 52428800},
				{"lookback_days", "Days of history used for the baseline", 14},
				{"min_samples", "Minimum baseline samples before alerting", 5},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				hour := e.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
				hits, err := e.DB.DetectVolumeAnomalies(ctx, hour, p.Int("lookback_days"), p.Int("min_samples"), int64(p.Int("min_bytes")), p.Float("factor"))
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					out = append(out, db.Finding{Host: h.Host, Key: hour.Format("2006010215"),
						Title:   fmt.Sprintf("%s sent %s in the hour starting %s (baseline %s)", h.Host, fmtBytes(h.BytesOut), hour.Format("15:04 UTC"), fmtBytes(int64(h.Median))),
						Details: map[string]any{"hour": hour, "bytes_out": h.BytesOut, "median": h.Median, "mad": h.MAD, "samples": h.Samples}})
				}
				return out, nil
			},
		},
		{
			Name: "new_host", Title: "New device on the network", Severity: db.SevInfo,
			Description: "A local address appeared for the first time (requires at least a day of rollup history).",
			Interval:    5 * time.Minute, Window: 2 * time.Hour,
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				hits, err := e.DB.DetectNewHosts(ctx, w.Since, 24*time.Hour)
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					out = append(out, db.Finding{Host: h.Host, Title: fmt.Sprintf("new device %s first seen %s", h.Host, h.FirstSeen.Local().Format("Jan 2 15:04")),
						Details: map[string]any{"first_seen": h.FirstSeen, "bytes": h.Bytes}})
				}
				return out, nil
			},
		},
		{
			Name: "new_destination", Title: "New destination network", Severity: db.SevWarning,
			Description: "A host contacted an ASN it never used during the lookback, and the peer is a hosting/proxy address, threat-listed, reputation-flagged, or the device is tagged IoT.",
			Interval:    5 * time.Minute, Window: time.Hour,
			Params: []Param{
				{"lookback_days", "History window for what counts as known", 30},
				{"min_history_days", "Days of history a host needs before this rule applies to it", 3},
				{"min_malicious", "VirusTotal engines for a peer to count as flagged", 2},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				hits, err := e.DB.DetectNewDestinations(ctx, w, e.Cfg.LocalNetworksCIDR(), p.Int("lookback_days"), p.Int("min_malicious"), p.Int("min_history_days"))
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					asn := ""
					if h.ASN != nil {
						asn = *h.ASN
					}
					org := ""
					if h.ASOrg != nil {
						org = " " + *h.ASOrg
					}
					out = append(out, db.Finding{Host: h.Host, Peer: h.Peer, Key: asn,
						Title:   fmt.Sprintf("%s contacted new network %s%s via %s (%s)", h.Host, asn, org, h.Peer, strings.Join(h.Reasons, ", ")),
						Details: map[string]any{"asn": h.ASN, "as_org": h.ASOrg, "country": h.CountryCode, "bytes": h.Bytes, "reasons": h.Reasons, "history_days": h.HistoryDays}})
				}
				return out, nil
			},
		},
		{
			Name: "beaconing", Title: "Beaconing", Severity: db.SevWarning,
			Description: "A local host contacts the same external peer at regular intervals with near-constant sizes: the classic command-and-control heartbeat. DNS/NTP/discovery ports are ignored.",
			Interval:    30 * time.Minute, Window: 24 * time.Hour,
			Params: []Param{
				{"min_contacts", "Minimum number of contact minutes in the window", 24},
				{"min_gap_minutes", "Ignore pairs that talk more often than this (continuous streams)", 2.0},
				{"max_cv", "Maximum coefficient of variation of the gaps (lower = more regular)", 0.2},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				hits, err := e.DB.DetectBeacons(ctx, w, e.Cfg.LocalNetworksCIDR(), e.gatewayList(), p.Int("min_contacts"), p.Float("min_gap_minutes"), p.Float("max_cv"))
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					out = append(out, db.Finding{Host: h.Host, Peer: h.Peer, Port: h.Port,
						Title:   fmt.Sprintf("%s beacons to %s:%d every ~%.0f min (%d times, gap CV %.2f)", h.Host, h.Peer, h.Port, h.AvgGapMin, h.Contacts, h.GapCV),
						Details: map[string]any{"contacts": h.Contacts, "avg_gap_min": h.AvgGapMin, "gap_cv": h.GapCV, "avg_bytes": h.AvgBytes, "port": h.Port, "first": h.First, "last": h.Last}})
				}
				return out, nil
			},
		},
		{
			Name: "long_lived", Title: "Long-lived tunnel", Severity: db.SevInfo,
			Description: "A local host kept a connection to a hosting/proxy/VPN address alive for many hours: remote access tunnel, VPN, or persistent C2 channel.",
			Interval:    time.Hour, Window: 24 * time.Hour,
			Params: []Param{
				{"min_hours", "Distinct hours the pair must be active within the window", 6},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				hits, err := e.DB.DetectLongLived(ctx, w, e.Cfg.LocalNetworksCIDR(), e.gatewayList(), p.Int("min_hours"))
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					out = append(out, db.Finding{Host: h.Host, Peer: h.Peer, Port: h.Port,
						Title:   fmt.Sprintf("%s kept %s:%d (%s) alive for %d hours", h.Host, h.Peer, h.Port, strings.Join(h.Reasons, "/"), h.Hours),
						Details: map[string]any{"hours": h.Hours, "bytes": h.Bytes, "reasons": h.Reasons, "port": h.Port}})
				}
				return out, nil
			},
		},
		{
			Name: "iot_fanout", Title: "IoT device talking to many networks", Severity: db.SevWarning,
			Description: "A device tagged as IoT (or another selected kind) contacted many distinct ASNs. Cameras, plugs and TVs normally talk to a handful of vendor networks.",
			Interval:    30 * time.Minute, Window: 24 * time.Hour,
			Params: []Param{
				{"kinds", "Device kinds this applies to", []any{"iot"}},
				{"min_asns", "Distinct ASNs within the window", 30},
			},
			run: func(ctx context.Context, e *Engine, r *Rule, p params, w db.Window) ([]db.Finding, error) {
				hits, err := e.DB.DetectIoTFanout(ctx, w, e.Cfg.LocalNetworksCIDR(), p.Strings("kinds"), p.Int("min_asns"))
				if err != nil {
					return nil, err
				}
				var out []db.Finding
				for _, h := range hits {
					out = append(out, db.Finding{Host: h.Host,
						Title:   fmt.Sprintf("%s (%s) talked to %d networks / %d peers in 24h", h.Host, h.Kind, h.ASNs, h.Peers),
						Details: map[string]any{"kind": h.Kind, "asns": h.ASNs, "peers": h.Peers}})
				}
				return out, nil
			},
		},
	}
}
