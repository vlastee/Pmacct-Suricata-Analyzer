package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// An alert card answers a tier-1 analyst's first question, "what caused this?", in one message:
// which machine and program, what the traffic looked like, what names the peer goes by, who
// flagged it and how, what happened to the traffic, and where to pivot in the UI.

// alertCtx is everything known about one alert. Gathering (DB) and rendering (pure) are split so
// the format can be tested without a database.
type alertCtx struct {
	Alert  db.Alert
	Window db.Window // the traffic window the card describes (UTC)
	Host   *ipCard
	Peer   *ipCard

	Agent *db.Agent
	Procs []db.EndpointProcess
	Ident map[string]*db.ProgramIdentity // by exe
	Files map[string]*db.FileIntel       // by sha256

	Traffic  *db.PairTraffic
	History  *db.PairHistory
	HistDays int // lookback of History

	Names    []db.IPName
	PeerInfo *db.IPInfo
	VTDets   []db.VTDetection
	VTDetsOK bool // engine names were stored at the last lookup
	Reps     []db.Reputation
	Lists    []string

	IDSEvent *db.IDSEvent
	IDS      []db.IDSPairStat

	BaseURL string
}

const (
	cardLookback   = 15 * time.Minute // traffic before the alert's first sighting
	cardTrailing   = 2 * time.Minute
	cardHistDays   = 7
	maxCardChars   = 3500 // one card must fit a Telegram message with room to spare
	maxCmdlineChar = 220
)

// gather fills an alertCtx from the database. Failures of individual look-ups are logged and
// leave that section empty: a partial card is better than no notification.
func (d *Dispatcher) gather(ctx context.Context, a db.Alert, cards map[string]*ipCard) *alertCtx {
	c := &alertCtx{Alert: a, HistDays: cardHistDays}
	if d.Cfg != nil {
		c.BaseURL = d.Cfg.PublicURL
	}
	first, last := a.FirstSeen, a.LastSeen
	if first.IsZero() {
		first = d.Now()
	}
	if last.Before(first) {
		last = first
	}
	c.Window = db.Window{Since: first.Add(-cardLookback).UTC(), Until: last.Add(cardTrailing).UTC()}
	if a.Host != nil {
		c.Host = cards[*a.Host]
	}
	if a.Peer != nil {
		c.Peer = cards[*a.Peer]
	}
	if d.DB == nil {
		return c
	}
	warn := func(what string, err error) {
		if err != nil {
			slog.Warn("alert card", "alert", a.ID, "part", what, "err", err)
		}
	}
	var err error
	host, peer := strOr(a.Host), strOr(a.Peer)
	if host != "" {
		c.Agent, err = d.DB.AgentForHost(ctx, host)
		warn("agent", err)
	}
	if host != "" && peer != "" {
		c.Procs, err = d.DB.EndpointProcessesFor(ctx, host, peer, c.Window, 3)
		warn("processes", err)
		c.Traffic, err = d.DB.PairTraffic(ctx, host, peer, c.Window)
		warn("traffic", err)
		c.History, err = d.DB.PairHistory(ctx, host, peer, c.Window.Until.AddDate(0, 0, -cardHistDays))
		warn("history", err)
		c.IDS, err = d.DB.IDSForPair(ctx, host, peer, c.Window, 3)
		warn("ids", err)
	}
	if len(c.Procs) > 0 {
		c.Ident, c.Files = map[string]*db.ProgramIdentity{}, map[string]*db.FileIntel{}
		for _, p := range c.Procs {
			if _, done := c.Ident[p.Exe]; !done && p.Exe != "" {
				id, err := d.DB.IdentityFor(ctx, p.AgentID, p.Exe)
				warn("identity", err)
				c.Ident[p.Exe] = id
			}
			if _, done := c.Files[p.SHA256]; !done && len(p.SHA256) == 64 {
				fi, err := d.DB.FileIntelFor(ctx, p.SHA256)
				warn("file intel", err)
				c.Files[p.SHA256] = fi
			}
		}
	}
	if peer != "" {
		c.Names, err = d.DB.IPNames(ctx, peer, 3)
		warn("names", err)
		c.PeerInfo, err = d.DB.GetIPInfo(ctx, peer)
		warn("ip info", err)
		c.VTDets, c.VTDetsOK, err = d.DB.VTDetectionsFor(ctx, peer)
		warn("vt engines", err)
		c.Reps, err = d.DB.ReputationFor(ctx, peer)
		warn("reputation", err)
		c.Lists, err = d.DB.ThreatListsFor(ctx, peer)
		warn("threat lists", err)
	}
	if id := idsEventID(a.Details); id > 0 {
		c.IDSEvent, err = d.DB.GetIDSEvent(ctx, id)
		warn("ids event", err)
	}
	return c
}

func strOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func idsEventID(details []byte) int64 {
	var d struct {
		ID int64 `json:"ids_event_id"`
	}
	if len(details) == 0 || json.Unmarshal(details, &d) != nil {
		return 0
	}
	return d.ID
}

// ---- rendering ----

var sevIcon = map[string]string{db.SevCritical: "🚨", db.SevWarning: "⚠️", db.SevInfo: "ℹ️"}

func utc(t time.Time) string      { return t.UTC().Format("2006-01-02 15:04 UTC") }
func utcHM(t time.Time) string    { return t.UTC().Format("15:04") }
func sameDay(a, b time.Time) bool { return a.UTC().Format("20060102") == b.UTC().Format("20060102") }

// span renders a UTC time range compactly: "2026-11-22 20:01–20:14 UTC (13 min)".
func span(a, b time.Time) string {
	dur := b.Sub(a).Round(time.Minute)
	ds := ""
	switch {
	case dur >= 2*time.Hour:
		ds = fmt.Sprintf(" (%.1f h)", dur.Hours())
	case dur > 0:
		ds = fmt.Sprintf(" (%d min)", int(dur.Minutes()))
	}
	if sameDay(a, b) {
		return a.UTC().Format("2006-01-02 15:04") + "–" + utcHM(b) + " UTC" + ds
	}
	return utc(a) + " – " + utc(b) + ds
}

func human(n int64) string {
	f := float64(n)
	for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
		if f < 1024 || u == "TB" {
			if u == "B" {
				return fmt.Sprintf("%d B", n)
			}
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return ""
}

func plural(n int64, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func svc(proto, port int) string {
	s := fmt.Sprintf("%s/%d", strings.ToUpper(db.ProtoName(proto)), port)
	if name := db.ServiceName(port); name != "" {
		s += " (" + name + ")"
	}
	return s
}

func short(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

func intOf(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// render produces the card text. now is used for "last seen … ago".
func (c *alertCtx) render(now time.Time) string {
	a := c.Alert
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	section := func(title string) { b.WriteString("\n" + title + "\n") }
	cards := map[string]*ipCard{}
	for _, ic := range []*ipCard{c.Host, c.Peer} {
		if ic != nil {
			cards[ic.IP] = ic
		}
	}
	host, peer := strOr(a.Host), strOr(a.Peer)

	// Header: severity, rule, stable id, what happened, how often.
	icon := sevIcon[a.Severity]
	if icon == "" {
		icon = "•"
	}
	line("%s %s · %s · alert #%d", icon, strings.ToUpper(a.Severity), a.Rule, a.ID)
	line("%s", labelIPs(a.Title, cards))
	seen := fmt.Sprintf("Alert seen %s", plural(int64(max(a.Count, 1)), "time"))
	switch {
	case a.FirstSeen.IsZero():
	case a.Count > 1 && !a.LastSeen.IsZero():
		seen += " · first " + utc(a.FirstSeen) + " · last " + utc(a.LastSeen)
	default:
		seen += " · " + utc(a.FirstSeen)
	}
	line("%s", seen)

	// 🖥️ Host: who / what the local machine is.
	if host != "" {
		section("🖥️ Host")
		label := host
		if c.Host != nil {
			label = c.Host.Label()
		} else if a.HostName != nil {
			label = *a.HostName + " (" + host + ")"
		}
		if c.Host != nil && c.Host.Kind != "" && c.Host.Kind != "other" {
			label += " · " + c.Host.Kind
		}
		line("%s", label)
		if ag := c.Agent; ag != nil {
			parts := []string{"agent " + firstNonEmpty(ag.Name, ag.Hostname)}
			if ag.Hostname != "" && ag.Hostname != ag.Name {
				parts = append(parts, "hostname "+ag.Hostname)
			}
			if ag.OS != "" {
				parts = append(parts, strings.TrimSpace(ag.OS+" "+ag.Arch))
			}
			if ag.LastSeen != nil {
				parts = append(parts, "last report "+ago(now, *ag.LastSeen))
			}
			line("%s", strings.Join(parts, " · "))
			if users := procUsers(c.Procs); users != "" {
				line("User(s): %s", users)
			}
		} else {
			line("No endpoint agent on this address, so the program and user can't be identified.")
		}
		if c.Host != nil && c.Host.Note != "" {
			line("Note: %s", c.Host.Note)
		}
	}

	// ⚙️ Process: the program behind the connection.
	if host != "" && peer != "" && c.Agent != nil {
		section("⚙️ Process")
		if len(c.Procs) == 0 {
			if via := viaOf(a.Details); via != "" {
				line("Reported by the rule: %s", via)
			} else {
				line("The agent didn't attribute any connection to %s to a program in this window.", peer)
			}
		}
		for i, p := range c.Procs {
			if i > 0 {
				b.WriteString("\n")
			}
			name := firstNonEmpty(p.Name, p.Exe)
			head := name
			if p.PID > 0 {
				head += fmt.Sprintf(" · pid %d", p.PID)
				if p.PIDs > 1 {
					head += fmt.Sprintf(" (+%d other pids)", p.PIDs-1)
				}
			}
			if p.User != "" {
				head += " · user " + p.User
			}
			if p.Container != "" {
				head += " · container " + p.Container
			}
			line("%s", head)
			if p.Exe != "" && p.Exe != name {
				line("Path: %s", p.Exe)
			}
			if p.Cmdline != "" {
				line("Cmd: %s", short(p.Cmdline, maxCmdlineChar))
			}
			facts := []string{fmt.Sprintf("%s to this peer", plural(p.Conns, "connection"))}
			if len(p.Ports) > 0 {
				ps := make([]string, 0, len(p.Ports))
				for _, port := range p.Ports {
					ps = append(ps, fmt.Sprint(port))
				}
				facts = append(facts, "port "+strings.Join(ps, ","))
			}
			line("%s", strings.Join(facts, " · "))
			if id := c.Ident[p.Exe]; id != nil {
				if s := identityLine(id); s != "" {
					line("%s", s)
				}
			}
			if len(p.SHA256) == 64 {
				s := "sha256 " + p.SHA256[:16] + "…"
				if fi := c.Files[p.SHA256]; fi != nil && fi.VT.Status == "ok" {
					total := intOf(fi.VT.Malicious) + intOf(fi.VT.Suspicious) + intOf(fi.VT.Harmless) + intOf(fi.VT.Undetected)
					s += fmt.Sprintf(" · file on VirusTotal: %d/%d malicious", intOf(fi.VT.Malicious), total)
					if fi.VT.Label != "" {
						s += " (" + fi.VT.Label + ")"
					}
				}
				line("%s", s)
			}
		}
	}

	// 🔌 Traffic: what the flows actually were.
	if host != "" && peer != "" {
		section("🔌 Traffic")
		t := c.Traffic
		if t == nil {
			line("No flow records between %s and %s in %s.", host, peer, span(c.Window.Since, c.Window.Until))
		} else {
			if t.First != nil && t.Last != nil {
				line("%s", span(*t.First, *t.Last))
			}
			if len(t.Services) > 0 {
				var ss []string
				for _, s := range t.Services {
					ss = append(ss, fmt.Sprintf("%s ×%d", svc(s.Proto, s.Port), s.Flows))
				}
				dir := "→"
				if t.Inbound {
					dir = "← inbound"
				}
				line("%s %s", dir, strings.Join(ss, ", "))
			}
			line("Out %s / %s in %s · In %s / %s in %s",
				plural(t.PacketsOut, "pkt"), human(t.BytesOut), plural(t.FlowsOut, "flow"),
				plural(t.PacketsIn, "pkt"), human(t.BytesIn), plural(t.FlowsIn, "flow"))
		}
		if h := c.History; h != nil && h.Flows > 0 {
			s := fmt.Sprintf("Pair history (%dd): %s on %s", c.HistDays, plural(h.Flows, "flow record"), plural(h.Days, "day"))
			if h.First != nil {
				s += ", first " + utc(*h.First)
				if !h.First.Before(c.Window.Since) {
					s += " (no contact before this alert)"
				}
			}
			line("%s", s)
		}
	}

	// 🛡️ Outcome: what happened to the traffic, stated plainly.
	if out := c.outcome(); out != "" {
		section("🛡️ Outcome")
		line("%s", out)
	}

	// 🌐 Names: what the peer is called on this network.
	if peer != "" {
		section("🌐 Names")
		if len(c.Names) == 0 {
			if c.Peer != nil && c.Peer.Name != "" {
				line("%s (reverse DNS / enrichment)", c.Peer.Name)
			} else {
				line("No DNS answer, TLS SNI or HTTP Host seen for %s.", peer)
			}
		}
		for _, n := range c.Names {
			src := map[string]string{"dns": "DNS answer", "tls": "TLS SNI", "http": "HTTP Host"}[n.Source]
			if src == "" {
				src = n.Source
			}
			line("%s · %s · %s · last %s", n.Name, src, plural(int64(n.Hits), "hit"), utc(n.LastSeen))
		}
		if len(c.Names) > 0 {
			line("(From Suricata on the LAN; which client asked and which resolver answered isn't recorded.)")
		}
	}

	// 🏷️ Verdict: who flagged the peer, exactly.
	if peer != "" {
		if v := c.verdict(); v != "" {
			section("🏷️ Verdict (flag is on the IP " + peer + ")")
			b.WriteString(v)
		}
	}

	// 🧾 IDS: Suricata's view of the same traffic.
	if ev := c.IDSEvent; ev != nil {
		section("🧾 Suricata")
		line("%s", idsEventLine(ev))
	} else if len(c.IDS) > 0 {
		section("🧾 Suricata (same pair, same window)")
		for _, s := range c.IDS {
			act := s.Action
			if act == "" {
				act = "action n/a"
			}
			l := fmt.Sprintf("sid %d · %s · ×%d · sev %d · %s", s.SID, short(s.Signature, 90), s.Events, s.Severity, act)
			if s.Iface != "" {
				l += " · " + s.Iface
			}
			line("%s", l)
		}
	}

	// 🔗 Pivots.
	if links := c.links(); len(links) > 0 {
		section("🔗 Pivot")
		for _, l := range links {
			line("%s", l)
		}
	}
	out := strings.TrimSpace(b.String())
	if r := []rune(out); len(r) > maxCardChars {
		out = string(r[:maxCardChars]) + "…"
	}
	return out
}

// outcome explains what happened to the traffic, with the counts that prove it.
func (c *alertCtx) outcome() string {
	if ev := c.IDSEvent; ev != nil && ev.Action != nil && *ev.Action != "" {
		switch *ev.Action {
		case "blocked", "drop", "dropped", "rejected":
			return "Blocked by Suricata (inline IPS mode)."
		default:
			return fmt.Sprintf("Suricata only alerted (action %q): the traffic was not blocked by the IDS.", *ev.Action)
		}
	}
	t := c.Traffic
	if t == nil {
		return ""
	}
	switch {
	case t.FlowsOut > 0 && t.FlowsIn == 0:
		s := fmt.Sprintf("One-way only: %s sent, 0 received. The flow sensor (softflowd on the LAN) sees packets before pfSense filters them, so pfSense either dropped them or the peer never answered (timeout). The analyzer has no firewall-log feed, so it can't tell which.",
			plural(t.PacketsOut, "packet"))
		if tcpOnly(t.Services) && t.FlowsOut > 0 {
			per := float64(t.PacketsOut) / float64(t.FlowsOut)
			if per <= 3 {
				s += fmt.Sprintf(" ~%.1f packets per flow fits connection attempts (SYN retries) only; TCP flags aren't exported, so this is inferred.", per)
			}
		}
		return s
	case t.FlowsIn > 0 && t.FlowsOut == 0:
		return fmt.Sprintf("Inbound only: %s from the peer, nothing sent back by %s (unanswered or dropped).", plural(t.PacketsIn, "packet"), strOr(c.Alert.Host))
	case t.FlowsIn > 0 && t.FlowsOut > 0:
		return fmt.Sprintf("Two-way: the connection got through and the peer answered (%s back). Not blocked.", plural(t.PacketsIn, "packet"))
	}
	return ""
}

func tcpOnly(ss []db.PairService) bool {
	if len(ss) == 0 {
		return false
	}
	for _, s := range ss {
		if s.Proto != 6 {
			return false
		}
	}
	return true
}

// verdict lists every source that has an opinion on the peer, with exact counts and engines.
func (c *alertCtx) verdict() string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	peer := strOr(c.Alert.Peer)
	if i := c.PeerInfo; i != nil && i.VT != nil && i.VT.Status == "ok" {
		v := i.VT
		total := intOf(v.Malicious) + intOf(v.Suspicious) + intOf(v.Harmless) + intOf(v.Undetected)
		s := fmt.Sprintf("VirusTotal: %d malicious, %d suspicious of %d engines", intOf(v.Malicious), intOf(v.Suspicious), total)
		if v.LastAnalysis != nil {
			s += " · analysed " + v.LastAnalysis.UTC().Format("2006-01-02")
		}
		if v.Reputation != nil {
			s += fmt.Sprintf(" · community score %d", *v.Reputation)
		}
		line("%s", s)
		if len(c.VTDets) > 0 {
			var es []string
			for i, d := range c.VTDets {
				if i == 8 {
					es = append(es, fmt.Sprintf("+%d more", len(c.VTDets)-8))
					break
				}
				r := d.Result
				if r == "" || r == d.Category {
					r = d.Category
				} else if d.Category == "suspicious" {
					r += ", suspicious"
				}
				es = append(es, d.Engine+" ("+r+")")
			}
			line("Engines: %s", strings.Join(es, ", "))
		} else if !c.VTDetsOK && intOf(v.Malicious)+intOf(v.Suspicious) > 0 {
			line("Engines: names arrive with the next VirusTotal refresh of this IP.")
		}
		if len(v.Tags) > 0 {
			line("VT tags: %s", strings.Join(v.Tags, ", "))
		}
		line("https://www.virustotal.com/gui/ip-address/%s", peer)
	}
	sort.Slice(c.Reps, func(i, j int) bool { return c.Reps[i].Source < c.Reps[j].Source })
	for _, r := range c.Reps {
		if r.Status != "ok" {
			continue
		}
		verdict := "not flagged"
		if r.Flagged {
			verdict = "FLAGGED"
		}
		s := ""
		switch r.Source {
		case "abuseipdb":
			s = fmt.Sprintf("AbuseIPDB: %s", verdict)
			if r.Score != nil {
				s += fmt.Sprintf(", confidence %d%%", *r.Score)
			}
			s += " · https://www.abuseipdb.com/check/" + peer
		case "greynoise":
			s = "GreyNoise: " + verdict
			if cls := jsonStr(r.Data, "classification"); cls != "" {
				s += " (" + cls + ")"
			}
		case "otx":
			s = "AlienVault OTX: " + verdict
			if r.Score != nil {
				s += fmt.Sprintf(", %d pulse(s)", *r.Score)
			}
		default:
			s = r.Source + ": " + verdict
			if r.Score != nil {
				s += fmt.Sprintf(" (score %d)", *r.Score)
			}
		}
		line("%s · checked %s", s, r.LookupAt.UTC().Format("2006-01-02"))
	}
	if len(c.Lists) > 0 {
		line("Threat lists: %s", strings.Join(c.Lists, ", "))
	}
	if p := c.Peer; p != nil {
		var net []string
		for _, s := range []string{p.Org, p.Geo} {
			if s != "" {
				net = append(net, s)
			}
		}
		if c.PeerInfo != nil && c.PeerInfo.ASN != nil && *c.PeerInfo.ASN != "" {
			net = append(net, *c.PeerInfo.ASN)
		}
		for _, f := range p.Flags {
			if f == "hosting" || f == "proxy/VPN" {
				net = append(net, f)
			}
		}
		if len(net) > 0 {
			line("Network: %s", strings.Join(net, " · "))
		}
	}
	return b.String()
}

func jsonStr(raw json.RawMessage, key string) string {
	var m map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func identityLine(id *db.ProgramIdentity) string {
	var parts []string
	switch {
	case id.Signature != "" && id.Signer != "":
		parts = append(parts, "signature "+id.Signature+" ("+id.Signer+")")
	case id.Signature != "":
		parts = append(parts, "signature "+id.Signature)
	}
	if id.Verified != nil {
		if *id.Verified {
			parts = append(parts, "matches package "+firstNonEmpty(id.Package, "manifest"))
		} else {
			parts = append(parts, "DOES NOT match its package "+id.Package)
		}
	}
	prod := strings.TrimSpace(strings.Join(nonEmpty(id.Company, id.Product, id.FileVersion), " "))
	if prod != "" {
		parts = append(parts, prod)
	}
	if id.Origin != "" {
		parts = append(parts, "origin "+id.Origin)
	}
	return strings.Join(parts, " · ")
}

func idsEventLine(ev *db.IDSEvent) string {
	var parts []string
	if ev.SID != nil {
		s := fmt.Sprintf("sid %d", *ev.SID)
		if rev := jsonPath(ev.Raw, "alert", "rev"); rev != "" {
			s += " rev " + rev
		}
		parts = append(parts, s)
	}
	if ev.Signature != nil {
		parts = append(parts, *ev.Signature)
	}
	if ev.Category != nil && *ev.Category != "" {
		parts = append(parts, *ev.Category)
	}
	if ev.Severity != nil {
		parts = append(parts, fmt.Sprintf("sev %d", *ev.Severity))
	}
	if ev.Action != nil {
		parts = append(parts, "action "+*ev.Action)
	}
	flow := ""
	if ev.SrcIP != nil && ev.DstIP != nil {
		flow = fmt.Sprintf("%s:%d → %s:%d", *ev.SrcIP, intOf(ev.SrcPort), *ev.DstIP, intOf(ev.DstPort))
		if ev.Proto != nil {
			flow += " " + *ev.Proto
		}
		if ev.AppProto != nil && *ev.AppProto != "" {
			flow += "/" + *ev.AppProto
		}
	}
	sensor := strings.TrimSpace(strings.Join(nonEmpty(jsonPath(ev.Raw, "host"), jsonPath(ev.Raw, "in_iface"), jsonPath(ev.Raw, "direction")), " · "))
	out := strings.Join(parts, " · ")
	if flow != "" {
		out += "\n" + flow
	}
	if sensor != "" {
		out += "\nSensor: " + sensor
	}
	return out + "\nEvent at " + utc(ev.TS)
}

// jsonPath reads a scalar from raw JSON ("alert","rev") as text.
func jsonPath(raw json.RawMessage, keys ...string) string {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return ""
	}
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = m[k]
	}
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%g", x)
	}
	return ""
}

// links builds pivots into the UI: the alert list, the host, the raw flows for the window, the IDS event.
func (c *alertCtx) links() []string {
	if c.BaseURL == "" {
		return nil
	}
	base := strings.TrimRight(c.BaseURL, "/") + "/#"
	host, peer := strOr(c.Alert.Host), strOr(c.Alert.Peer)
	win := url.Values{}
	win.Set("since", c.Window.Since.UTC().Format(time.RFC3339))
	win.Set("until", c.Window.Until.UTC().Format(time.RFC3339))
	var out []string
	if host != "" {
		q := url.Values{"host": {host}}
		out = append(out, fmt.Sprintf("Alert #%d: %s/alerts?%s", c.Alert.ID, base, q.Encode()))
		out = append(out, fmt.Sprintf("Host: %s/hosts/%s?%s", base, url.PathEscape(host), win.Encode()))
	} else {
		out = append(out, fmt.Sprintf("Alert #%d: %s/alerts", c.Alert.ID, base))
	}
	if ip := firstNonEmpty(peer, host); ip != "" {
		q := url.Values{"ip": {ip}, "since": win["since"], "until": win["until"]}
		if t := c.Traffic; t != nil && len(t.Services) == 1 {
			q.Set("port", fmt.Sprint(t.Services[0].Port))
		}
		out = append(out, fmt.Sprintf("Raw flows: %s/flows?%s", base, q.Encode()))
	}
	if ev := c.IDSEvent; ev != nil {
		out = append(out, fmt.Sprintf("IDS event: %s/ids?event=%d", base, ev.ID))
	} else if len(c.IDS) > 0 {
		out = append(out, fmt.Sprintf("IDS event: %s/ids?event=%d", base, c.IDS[0].LastID))
	}
	return out
}

func procUsers(ps []db.EndpointProcess) string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ps {
		if p.User != "" && !seen[p.User] {
			seen[p.User] = true
			out = append(out, p.User)
		}
	}
	return strings.Join(out, ", ")
}

func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return utc(t)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
