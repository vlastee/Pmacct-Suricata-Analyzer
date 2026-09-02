package explain

import (
	"context"
	"fmt"
	"net"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// Request selects the program to explain.
type Request struct {
	AgentID   int64
	Host      string
	Exe       string
	User      string
	Container string
	Window    db.Window
}

// Program is the identity section of the report.
type Program struct {
	Name          string     `json:"name"`
	Exe           string     `json:"exe"`
	User          string     `json:"user"`
	Container     string     `json:"container,omitempty"`
	OS            string     `json:"os,omitempty"`
	Machine       string     `json:"machine,omitempty"`
	Hashes        []string   `json:"hashes"`
	Hosts         []string   `json:"hosts"`
	Agents        int64      `json:"agents"`
	Conns         int64      `json:"conns"`
	Destinations  int        `json:"destinations"`
	FirstSeen     *time.Time `json:"first_seen"`
	LastSeen      *time.Time `json:"last_seen"`
	FirstInWindow *time.Time `json:"first_in_window"`
	Pids          []int      `json:"pids"`
	Cmdline       string     `json:"cmdline,omitempty"`
	Known         *Known     `json:"known"`
	KnownSource   string     `json:"known_source,omitempty"` // "user" | "builtin" | "lolbas" | "gtfobins"
	KnownID       int64      `json:"known_id,omitempty"`     // user entry id (for editing)
	// Facts from the machine itself (agent ≥ 0.3): package / signer / manifest check.
	Identity *db.ProgramIdentity `json:"identity"`
	// Keyed look-ups by hash: VirusTotal file report, Team Cymru MHR.
	File *db.FileIntel `json:"file"`
	// Catalogue entry when the name is a known living-off-the-land binary.
	LOLBin *db.LOLBin `json:"lolbin"`
}

// Destination is one peer with everything we know about it.
type Destination struct {
	Dst               string    `json:"dst"`
	Port              int       `json:"port"`
	Proto             string    `json:"proto"`
	Service           string    `json:"service,omitempty"`
	Conns             int64     `json:"conns"`
	Bytes             int64     `json:"bytes"`
	First             time.Time `json:"first"`
	Last              time.Time `json:"last"`
	Hostname          string    `json:"hostname,omitempty"`
	Names             []string  `json:"names"`
	ASN               string    `json:"asn,omitempty"`
	Org               string    `json:"org,omitempty"`
	Country           string    `json:"country,omitempty"`
	Hosting           bool      `json:"hosting"`
	Proxy             bool      `json:"proxy"`
	Infra             Infra     `json:"infra"`
	Lists             []string  `json:"lists"`
	VTMalicious       int       `json:"vt_malicious"`
	Reputation        []string  `json:"reputation"`
	OtherPrograms     []string  `json:"other_programs"`
	OtherProgramCount int64     `json:"other_program_count"`
	OtherHosts        int64     `json:"other_hosts"`
	OpenAlerts        int64     `json:"open_alerts"`
	AlertTitles       []string  `json:"alert_titles"`
	IDSEvents         int64     `json:"ids_events"`
	Notes             int64     `json:"notes"`
	Trusted           string    `json:"trusted,omitempty"`
	Beacon            *Beacon   `json:"beacon,omitempty"`
	Flags             []string  `json:"flags"`
}

type Signal struct {
	Level string `json:"level"` // info | warn | critical
	Text  string `json:"text"`
}

type Assessment struct {
	Level   string `json:"level"` // expected | review | suspicious
	Summary string `json:"summary"`
}

type Report struct {
	Program      Program       `json:"program"`
	Destinations []Destination `json:"destinations"`
	Signals      []Signal      `json:"signals"`
	Assessment   Assessment    `json:"assessment"`
	Verify       []string      `json:"verify"`
	Window       db.Window     `json:"window"`
	GeneratedAt  time.Time     `json:"generated_at"`
}

// Builder assembles reports from the database plus a reverse-DNS lookup.
type Builder struct {
	DB         *db.DB
	Now        func() time.Time
	LookupAddr func(ctx context.Context, ip string) []string // nil = net.DefaultResolver
}

func (b *Builder) rdns(ctx context.Context, ip string) []string {
	if b.LookupAddr != nil {
		return b.LookupAddr(ctx, ip)
	}
	ctx, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil
	}
	for i := range names {
		names[i] = strings.TrimSuffix(names[i], ".")
	}
	return names
}

// Build produces the report.
func (b *Builder) Build(ctx context.Context, req Request) (*Report, error) {
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	key := db.ProgramKey{AgentID: req.AgentID, Host: req.Host, Exe: req.Exe, User: req.User, Container: req.Container}
	sum, err := b.DB.ProgramSummaryFor(ctx, key, req.Window)
	if err != nil {
		return nil, err
	}
	rep := &Report{Window: req.Window, GeneratedAt: now().UTC(), Destinations: []Destination{}, Signals: []Signal{}, Verify: []string{}}
	name := ""
	if len(sum.Names) > 0 {
		name = sum.Names[0]
	}
	if name == "" && req.Exe != "" {
		name = path.Base(strings.ReplaceAll(req.Exe, `\`, "/"))
	}
	if name == "" {
		name = "(unknown process)"
	}
	rep.Program = Program{Name: name, Exe: req.Exe, User: req.User, Container: req.Container, Hashes: sum.Hashes, Hosts: sum.Hosts, Agents: sum.Agents,
		Conns: sum.Conns, FirstSeen: sum.FirstEver, LastSeen: sum.LastEver, FirstInWindow: sum.FirstInWindow, Pids: sum.Pids, Cmdline: sum.Cmdline}
	// User-maintained entries take precedence over the built-in knowledge base.
	if entries, err := b.DB.ListKB(ctx); err == nil && req.Exe != "" {
		if m := db.MatchKB(entries, name, req.Exe, sum.Hashes); m != nil {
			rep.Program.Known = &Known{Title: m.Title, Category: m.Category, Description: m.Description, Expected: m.Expected, Verify: m.Verify, Risk: m.Risk}
			rep.Program.KnownSource, rep.Program.KnownID = "user", m.ID
		}
	}
	if rep.Program.Known == nil && req.Exe != "" {
		if k := Lookup(name, req.Exe); k != nil {
			rep.Program.Known, rep.Program.KnownSource = k, "builtin"
		}
	}
	// Which machine / OS (for verify commands).
	var agent *db.Agent
	if req.AgentID > 0 {
		agent, _ = b.DB.AgentByID(ctx, req.AgentID)
	} else if req.Host != "" {
		agent, _ = b.DB.AgentForHost(ctx, req.Host)
	}
	if agent != nil {
		rep.Program.OS, rep.Program.Machine = agent.OS, agent.Name
		if req.Exe != "" {
			if id, err := b.DB.IdentityFor(ctx, agent.ID, req.Exe); err == nil && id != nil {
				rep.Program.Identity = id
			}
		}
	}
	// Hash intelligence: the identity's hash first (the file as it is now), then whatever the
	// window saw.
	var hashes []string
	if rep.Program.Identity != nil {
		hashes = append(hashes, rep.Program.Identity.SHA256)
	}
	hashes = append(hashes, sum.Hashes...)
	for _, h := range hashes {
		if h == "" {
			continue
		}
		if fi, err := b.DB.FileIntelFor(ctx, h); err == nil && fi != nil {
			rep.Program.File = fi
			break
		}
	}
	if name != "(unknown process)" {
		if l, err := b.DB.LOLBinFor(ctx, name, rep.Program.OS); err == nil && l != nil {
			rep.Program.LOLBin = l
			if rep.Program.Known == nil {
				rep.Program.Known, rep.Program.KnownSource = KnownFromLOLBin(l), l.Source
			}
		}
	}
	dests, err := b.DB.ProgramDestinationsFor(ctx, key, req.Window, 25)
	if err != nil {
		return nil, err
	}
	rep.Program.Destinations = len(dests)
	set, _ := b.DB.LoadExclusions(ctx)
	excl := sum.Hosts
	if req.Host != "" {
		excl = append(excl, req.Host)
	}
	lookups := 0
	for _, pd := range dests {
		d := Destination{Dst: pd.Dst, Port: pd.DstPort, Proto: pd.Proto, Service: db.ServiceName(pd.DstPort), Conns: pd.Conns, Bytes: pd.Bytes, First: pd.First, Last: pd.Last,
			Names: []string{}, Lists: []string{}, Reputation: []string{}, OtherPrograms: []string{}, AlertTitles: []string{}, Flags: []string{}}
		if info, err := b.DB.GetIPInfo(ctx, pd.Dst); err == nil && info != nil {
			d.Hostname = strOf(info.Hostname)
			d.ASN, d.Org, d.Country = strOf(info.ASN), firstOf(info.ASOrg, info.Org, info.ISP), strOf(info.CountryCode)
			d.Hosting, d.Proxy = boolOf(info.IsHosting), boolOf(info.IsProxy)
			if info.VT != nil && info.VT.Malicious != nil {
				d.VTMalicious = *info.VT.Malicious
			}
			d.Infra = Classify(strOf(info.Org), strOf(info.ISP), strOf(info.ASOrg), d.Hostname)
		} else {
			d.Infra = Classify("", "", "", "")
		}
		if names, err := b.DB.IPNames(ctx, pd.Dst, 5); err == nil {
			for _, n := range names {
				d.Names = append(d.Names, n.Name)
			}
		}
		if d.Hostname == "" && lookups < 15 {
			lookups++
			if rd := b.rdns(ctx, pd.Dst); len(rd) > 0 {
				d.Hostname = rd[0]
				d.Flags = append(d.Flags, "rdns-live")
				if d.Infra.Class == "unknown" {
					d.Infra = Classify("", "", "", d.Hostname)
				}
			}
		}
		if lists, err := b.DB.ThreatListsFor(ctx, pd.Dst); err == nil && len(lists) > 0 {
			d.Lists = lists
		}
		if reps, err := b.DB.ReputationFor(ctx, pd.Dst); err == nil {
			for _, r := range reps {
				if r.Flagged {
					switch {
					case r.Source == "abuseipdb" && r.Score != nil:
						d.Reputation = append(d.Reputation, fmt.Sprintf("AbuseIPDB %d%%", *r.Score))
					case r.Source == "otx" && r.Score != nil:
						d.Reputation = append(d.Reputation, fmt.Sprintf("OTX %d pulse(s)", *r.Score))
					default:
						d.Reputation = append(d.Reputation, r.Source+" flagged")
					}
				}
			}
		}
		if set != nil {
			if p, ok := set.Match(pd.Dst, append([]string{d.Hostname}, d.Names...)); ok {
				d.Trusted = p
			}
		}
		if c, err := b.DB.DestinationContextFor(ctx, pd.Dst, key, excl, req.Window); err == nil {
			d.OtherPrograms, d.OtherProgramCount, d.OtherHosts = c.OtherPrograms, c.OtherProgramCount, c.OtherHosts
			d.OpenAlerts, d.AlertTitles, d.IDSEvents, d.Notes = c.OpenAlerts, c.AlertTitles, c.IDSEvents, c.Notes
		}
		if bc, ok := Beaconish(pd.Minutes); ok {
			d.Beacon = &bc
			d.Flags = append(d.Flags, "beacon-like")
		}
		if d.OtherHosts == 0 && d.OtherProgramCount == 0 {
			d.Flags = append(d.Flags, "unique-to-this-program")
		}
		rep.Destinations = append(rep.Destinations, d)
	}
	Assess(rep, now())
	rep.Verify = verifyCommands(rep)
	return rep, nil
}

func strOf(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

func firstOf(ps ...*string) string {
	for _, p := range ps {
		if s := strOf(p); s != "" {
			return s
		}
	}
	return ""
}

func boolOf(p *bool) bool { return p != nil && *p }

var commonPorts = map[int]bool{80: true, 443: true, 53: true, 853: true, 123: true, 22: true, 25: true, 465: true, 587: true, 993: true, 995: true, 8080: true, 8443: true, 5228: true, 3478: true, 5222: true}

func suspiciousPath(exe string) bool {
	p := strings.ToLower(strings.ReplaceAll(exe, `\`, "/"))
	for _, frag := range []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/.cache/", "/downloads/", "/appdata/local/temp/", "/temp/", "/recycle", "/programdata/temp"} {
		if strings.Contains(p, frag) {
			return true
		}
	}
	return false
}

// Assess derives signals and the overall assessment from the gathered facts (pure; unit-tested).
func Assess(rep *Report, now time.Time) {
	var sig []Signal
	add := func(level, format string, a ...any) {
		sig = append(sig, Signal{Level: level, Text: fmt.Sprintf(format, a...)})
	}
	p := &rep.Program
	k := p.Known
	unknownOwner := p.Exe == "" && (p.Name == "" || p.Name == "(unknown process)")
	switch {
	case unknownOwner:
		hint := "Switch the agent to eBPF capture (auto/ebpf), which attributes connections at connect() time instead of polling."
		if strings.EqualFold(p.OS, "windows") {
			hint = "These are usually connections from processes that exited between two polls; the ETW backend will attribute them at connect time."
		}
		add("info", "Sockets whose owning process the agent could not resolve: the process exited before the next poll, or its file descriptors were not readable (another user's or a container's namespace without permission). %s", hint)
	case k == nil:
		add("info", "%s is not in the knowledge base — identify it by path, hash and destinations.", p.Name)
	case k.Risk == "no-network":
		add("critical", "%s is a core system process that should never open outbound connections; this points to code injection or a spoofed process name.", p.Name)
	case k.Risk == "lolbin":
		if p.LOLBin != nil {
			add("warn", "%s is a system utility listed by %s as abusable for %s; check the command line and the parent process.", p.Name, catalogueName(p.LOLBin.Source), strings.Join(p.LOLBin.Functions, ", "))
		} else {
			add("warn", "%s is a scriptable system utility that malware commonly abuses; check the command line and the parent process.", p.Name)
		}
	case k.Risk == "interpreter":
		add("info", "%s is an interpreter — the real identity is the script; enable command-line reporting to see it.", p.Name)
	}
	if l := p.LOLBin; l != nil && (k == nil || k.Risk != "lolbin") {
		add("warn", "%s is listed by %s as abusable for %s — check the command line and the parent process.", p.Name, catalogueName(l.Source), strings.Join(l.Functions, ", "))
	}
	if suspiciousPath(p.Exe) {
		add("warn", "Executable lives in a temporary/download location (%s) — legitimate software rarely runs from there.", p.Exe)
	}
	identitySignals(p, k, add)
	if p.Exe == "" && !unknownOwner {
		add("info", "The agent could not read the executable path (process exited quickly, or a kernel thread).")
	}
	if len(p.Hashes) > 1 {
		add("warn", "The binary changed during the window (%d different SHA-256 hashes) — an update, or a replaced file.", len(p.Hashes))
	}
	if p.FirstSeen != nil && now.Sub(*p.FirstSeen) < 24*time.Hour {
		add("info", "First seen on this machine %s — new program.", p.FirstSeen.Format("Jan 2 15:04"))
	}
	u := strings.ToLower(p.User)
	if (u == "root" || strings.HasSuffix(u, "\\system") || u == "system") && k == nil {
		add("warn", "Runs as %s and is not a known program.", p.User)
	}
	for _, d := range rep.Destinations {
		if d.Trusted != "" {
			continue
		}
		where := d.Dst
		if d.Hostname != "" {
			where = d.Hostname + " (" + d.Dst + ")"
		}
		if len(d.Lists) > 0 {
			add("critical", "%s is on threat list(s) %s.", where, strings.Join(d.Lists, ", "))
		}
		if d.VTMalicious >= 2 {
			add("critical", "%s is flagged malicious by %d VirusTotal engines.", where, d.VTMalicious)
		}
		if len(d.Reputation) > 0 {
			add("warn", "%s has a bad reputation: %s.", where, strings.Join(d.Reputation, ", "))
		}
		if d.Beacon != nil {
			add("warn", "Contacts %s every ~%.0f min with very regular timing (%d times, gap CV %.2f) — beacon-like.", where, d.Beacon.AvgGapMin, d.Beacon.Contacts, d.Beacon.GapCV)
		}
		unique := d.OtherHosts == 0 && d.OtherProgramCount == 0
		if unique && (d.Infra.Class == "hosting" || d.Infra.Class == "unknown" || d.Infra.Class == "isp") && d.Hostname == "" && d.Lists == nil {
			add("warn", "%s (%s) is contacted only by this program, has no reverse DNS and sits on a %s network — worth identifying.", d.Dst, d.Infra.Label, d.Infra.Class)
		}
		if !commonPorts[d.Port] && d.Proto == "tcp" && (d.Infra.Class == "hosting" || d.Infra.Class == "unknown" || d.Infra.Class == "isp") {
			add("info", "%s uses an uncommon port %d/%s on a %s network.", where, d.Port, d.Proto, d.Infra.Label)
		}
		if d.OpenAlerts > 0 {
			add("warn", "%s already has %d open alert(s): %s.", where, d.OpenAlerts, strings.Join(d.AlertTitles, "; "))
		}
	}
	if len(sig) == 0 {
		add("info", "Nothing unusual: known program, ordinary destinations, no reputation or timing anomalies.")
	}
	level, summary := "expected", ""
	crit, warn := 0, 0
	for _, s := range sig {
		switch s.Level {
		case "critical":
			crit++
		case "warn":
			warn++
		}
	}
	switch {
	case crit > 0:
		level = "suspicious"
		summary = fmt.Sprintf("%d critical finding(s) — investigate now.", crit)
	case warn > 0:
		level = "review"
		summary = fmt.Sprintf("%d thing(s) worth a look; nothing conclusive.", warn)
	default:
		if k != nil {
			summary = k.Title + " behaving as expected."
		} else {
			summary = "Unknown program, but nothing about its traffic stands out."
		}
	}
	sort.SliceStable(sig, func(i, j int) bool { return rank(sig[i].Level) > rank(sig[j].Level) })
	rep.Signals = sig
	rep.Assessment = Assessment{Level: level, Summary: summary}
}

func catalogueName(source string) string {
	switch source {
	case "lolbas":
		return "LOLBAS"
	case "gtfobins":
		return "GTFOBins"
	}
	return source
}

// KnownFromLOLBin turns a catalogue entry into a knowledge-base entry (used when neither the
// user nor the built-in list knows the program).
func KnownFromLOLBin(l *db.LOLBin) *Known {
	desc := l.Description
	if len(l.Functions) > 0 {
		desc += " Abusable for: " + strings.Join(l.Functions, ", ") + "."
	}
	return &Known{Title: "System utility listed by " + catalogueName(l.Source) + " (" + l.Display + ")", Category: "lolbin", Description: strings.TrimSpace(desc),
		Expected: "Normally nothing, or only what an administrator drives it to do; outbound connections from it deserve a look.", Risk: "lolbin"}
}

// identitySignals turns the agent's facts about the file and the hash look-ups into signals.
func identitySignals(p *Program, k *Known, add func(level, format string, a ...any)) {
	if id := p.Identity; id != nil {
		ver := id.PackageVersion
		if ver != "" {
			ver = " " + ver
		}
		switch {
		case id.Verified != nil && !*id.Verified:
			add("critical", "The file differs from what package %s%s installed (%s manifest mismatch) — a modified or replaced binary.", id.Package, ver, id.Origin)
		case id.Verified != nil && *id.Verified:
			add("info", "Installed by %s package %s%s; the file matches the package manifest.", id.Origin, id.Package, ver)
		case id.Package != "" && id.Origin != "container":
			add("info", "Installed by %s package %s%s.", id.Origin, id.Package, ver)
		}
		switch id.Origin {
		case "unpackaged":
			add("warn", "No package owns this file (%s) — it was placed there by hand, an installer script, or something else.", p.Exe)
		case "tmp", "download":
			if !suspiciousPath(p.Exe) {
				add("warn", "Runs from a temporary/download location (%s) — legitimate software rarely runs from there.", p.Exe)
			}
		case "home":
			add("info", "Lives in a user's home directory — a personal build or manual download, not managed by the system.")
		case "container":
			add("info", "Runs inside container %s; identify it by the image, not by the host's packages.", id.Package)
		}
		switch id.Signature {
		case "valid":
			by := id.Signer
			if by == "" {
				by = "an unnamed certificate"
			}
			how := ""
			if strings.HasPrefix(id.Note, "catalog") {
				how = " (Windows security catalog)"
			}
			add("info", "Authenticode signature valid — signed by %s%s.", by, how)
		case "unsigned":
			hint := ""
			if id.Company != "" {
				hint = " even though the version resource names " + id.Company
			}
			add("warn", "Not digitally signed%s — established vendors sign their releases, so an unsigned binary needs another reason to be trusted.", hint)
		case "untrusted":
			by := id.Signer
			if by == "" {
				by = "unknown signer"
			}
			add("warn", "Signed by %s, but the certificate chain is not trusted on this machine (%s) — a self-signed, expired or unknown-root certificate.", by, id.Note)
		case "invalid":
			add("critical", "The digital signature is INVALID — the file was modified after signing, or its certificate was revoked.")
		}
	}
	if f := p.File; f != nil {
		switch f.VT.Status {
		case "ok":
			m, total := 0, 0
			if f.VT.Malicious != nil {
				m = *f.VT.Malicious
			}
			for _, c := range []*int{f.VT.Malicious, f.VT.Suspicious, f.VT.Harmless, f.VT.Undetected} {
				if c != nil {
					total += *c
				}
			}
			label := ""
			if f.VT.Label != "" {
				label = " (" + f.VT.Label + ")"
			}
			switch {
			case m >= 3:
				add("critical", "%d of %d VirusTotal engines flag this file as malicious%s.", m, total, label)
			case m >= 1:
				add("warn", "%d of %d VirusTotal engines flag this file%s — likely a false positive, but check the vendor names.", m, total, label)
			default:
				first := ""
				if f.VT.FirstSeen != nil {
					first = ", first submitted " + f.VT.FirstSeen.Format("Jan 2006")
				}
				add("info", "VirusTotal: 0 of %d engines flag this file%s.", total, first)
			}
		case "unknown":
			level := "info"
			if id := p.Identity; id != nil && (id.Signature == "unsigned" || id.Signature == "untrusted" || id.Origin == "unpackaged" || id.Origin == "tmp" || id.Origin == "download") {
				level = "warn"
			}
			add(level, "This exact file has never been submitted to VirusTotal — no other party has seen it.")
		}
		if f.MHR.Status == "listed" {
			pct := ""
			if f.MHR.Detection != nil {
				pct = fmt.Sprintf("; %d%% of AV engines detect it", *f.MHR.Detection)
			}
			add("critical", "Team Cymru's Malware Hash Registry lists this file as known malware%s.", pct)
		}
	}
	_ = k
}

func rank(level string) int {
	switch level {
	case "critical":
		return 3
	case "warn":
		return 2
	}
	return 1
}

// verifyCommands lists what to run on the machine to confirm the picture.
func verifyCommands(rep *Report) []string {
	p := rep.Program
	pid := "<pid>"
	if len(p.Pids) > 0 {
		pid = fmt.Sprint(p.Pids[0])
	}
	var dst string
	if len(rep.Destinations) > 0 {
		dst = rep.Destinations[0].Dst
	}
	var out []string
	if strings.EqualFold(p.OS, "windows") {
		out = append(out, fmt.Sprintf("Get-Process -Id %s | Select-Object Path, StartTime, Company", pid))
		if p.Exe != "" {
			out = append(out, fmt.Sprintf("Get-AuthenticodeSignature '%s' | Select-Object Status, SignerCertificate", p.Exe), fmt.Sprintf("Get-FileHash '%s'   # compare with the reported sha256", p.Exe),
				fmt.Sprintf("(Get-Item '%s').VersionInfo | Format-List CompanyName, ProductName, FileVersion", p.Exe))
		}
		out = append(out, fmt.Sprintf("netstat -bano | findstr %s", pid))
		if dst != "" {
			out = append(out, fmt.Sprintf("Resolve-DnsName %s -Type PTR", dst))
		}
	} else {
		out = append(out, fmt.Sprintf("ps -o pid,user,etime,cmd -p %s", pid), fmt.Sprintf("readlink /proc/%s/exe", pid))
		if p.Exe != "" {
			out = append(out, fmt.Sprintf("sha256sum '%s'   # compare with the reported sha256", p.Exe))
			origin := ""
			if p.Identity != nil {
				origin = p.Identity.Origin
			}
			switch origin {
			case "dpkg":
				out = append(out, fmt.Sprintf("dpkg -S '%s' && dpkg -V %s   # owner, then verify the package's files", p.Exe, p.Identity.Package))
			case "apk":
				out = append(out, fmt.Sprintf("apk info -W '%s' && apk audit %s", p.Exe, p.Identity.Package))
			case "pacman":
				out = append(out, fmt.Sprintf("pacman -Qo '%s' && pacman -Qkk %s", p.Exe, p.Identity.Package))
			case "snap":
				out = append(out, fmt.Sprintf("snap list %s", p.Identity.Package))
			case "flatpak":
				out = append(out, fmt.Sprintf("flatpak info %s", p.Identity.Package))
			case "unpackaged", "":
				out = append(out, fmt.Sprintf("dpkg -S '%s' 2>/dev/null || rpm -qf '%s' 2>/dev/null || pacman -Qo '%s'   # which package owns it, if any", p.Exe, p.Exe, p.Exe))
			}
		}
		out = append(out, fmt.Sprintf("sudo ss -tnp | grep 'pid=%s'", pid))
		if dst != "" {
			out = append(out, fmt.Sprintf("dig -x %s +short", dst))
		}
		if p.Container != "" {
			out = append(out, fmt.Sprintf("podman exec %s ss -tn   # or: docker exec …", p.Container))
		}
	}
	if p.Known != nil {
		for _, v := range p.Known.Verify {
			out = append(out, strings.ReplaceAll(v, "<pid>", pid))
		}
	}
	return out
}
