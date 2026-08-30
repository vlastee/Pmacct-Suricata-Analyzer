package explain

import (
	"strings"
	"testing"
	"time"
)

func TestLookup(t *testing.T) {
	if k := Lookup("pasta.avx2", "/usr/bin/pasta.avx2"); k == nil || k.Category != "container-networking" || !strings.Contains(k.Description, "rootless Podman") {
		t.Fatalf("pasta: %+v", k)
	}
	if k := Lookup("", `C:\Program Files\Google\Chrome\Application\chrome.exe`); k == nil || k.Category != "browser" {
		t.Fatalf("chrome by path: %+v", k)
	}
	if k := Lookup("lsass.exe", ""); k == nil || k.Risk != "no-network" {
		t.Fatalf("lsass: %+v", k)
	}
	if k := Lookup("python3", "/usr/bin/python3"); k == nil || k.Risk != "interpreter" {
		t.Fatalf("python: %+v", k)
	}
	if Lookup("totally-unknown-thing", "/opt/x/bin/totally-unknown-thing") != nil {
		t.Fatal("unknown should be nil")
	}
}

func TestClassify(t *testing.T) {
	if i := Classify("Cloudflare, Inc.", "", "", ""); i.Class != "cdn" || i.Label != "Cloudflare" {
		t.Errorf("cloudflare: %+v", i)
	}
	if i := Classify("", "", "Hetzner Online GmbH", ""); i.Class != "hosting" {
		t.Errorf("hetzner: %+v", i)
	}
	if i := Classify("", "", "Anthropic, PBC", ""); i.Class != "vendor" {
		t.Errorf("anthropic: %+v", i)
	}
	if i := Classify("", "", "", ""); i.Class != "unknown" || !strings.Contains(i.Note, "Not enriched") {
		t.Errorf("empty: %+v", i)
	}
	if i := Classify("", "", "", "cdn7.fastly.example"); i.Class != "cdn" {
		t.Errorf("hostname only: %+v", i)
	}
}

func TestBeaconish(t *testing.T) {
	base := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	var regular []time.Time
	for i := 0; i < 10; i++ {
		regular = append(regular, base.Add(time.Duration(i)*10*time.Minute))
	}
	if b, ok := Beaconish(regular); !ok || b.AvgGapMin != 10 || b.GapCV != 0 {
		t.Errorf("regular: %+v %v", b, ok)
	}
	irregular := []time.Time{base, base.Add(1 * time.Minute), base.Add(2 * time.Minute), base.Add(40 * time.Minute), base.Add(41 * time.Minute), base.Add(90 * time.Minute), base.Add(91 * time.Minute)}
	if _, ok := Beaconish(irregular); ok {
		t.Error("irregular should not be beacon-like")
	}
	if _, ok := Beaconish(regular[:4]); ok {
		t.Error("too few contacts")
	}
	continuous := []time.Time{base, base.Add(time.Minute), base.Add(2 * time.Minute), base.Add(3 * time.Minute), base.Add(4 * time.Minute), base.Add(5 * time.Minute), base.Add(6 * time.Minute)}
	if _, ok := Beaconish(continuous); ok {
		t.Error("every-minute streams are not beacons")
	}
}

func TestAssess(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	old := now.Add(-72 * time.Hour)
	// Known browser talking to a CDN: expected.
	rep := &Report{Program: Program{Name: "chrome.exe", Exe: `C:\Program Files\Google\Chrome\chrome.exe`, User: "petro", FirstSeen: &old, Known: Lookup("chrome.exe", "")},
		Destinations: []Destination{{Dst: "104.16.1.1", Port: 443, Proto: "tcp", Hostname: "cdn.example", Infra: Classify("Cloudflare", "", "", ""), OtherHosts: 3}}}
	Assess(rep, now)
	if rep.Assessment.Level != "expected" || len(rep.Signals) != 1 || rep.Signals[0].Level != "info" {
		t.Fatalf("expected: %+v %+v", rep.Assessment, rep.Signals)
	}
	// lsass talking out + threat-listed peer: suspicious, critical signals first.
	rep = &Report{Program: Program{Name: "lsass.exe", Exe: `C:\Windows\System32\lsass.exe`, Known: Lookup("lsass.exe", "")},
		Destinations: []Destination{{Dst: "203.0.113.9", Port: 4444, Proto: "tcp", Infra: Classify("", "", "Hetzner", ""), Lists: []string{"feodo"}}}}
	Assess(rep, now)
	if rep.Assessment.Level != "suspicious" || rep.Signals[0].Level != "critical" {
		t.Fatalf("suspicious: %+v %+v", rep.Assessment, rep.Signals)
	}
	// Unknown program in /tmp with a beacon-like unique hosting peer: review.
	rep = &Report{Program: Program{Name: "x", Exe: "/tmp/.x/x", User: "petro"},
		Destinations: []Destination{{Dst: "5.6.7.8", Port: 8081, Proto: "tcp", Infra: Classify("", "", "OVH", ""), Beacon: &Beacon{Contacts: 20, AvgGapMin: 5, GapCV: 0.1}}}}
	Assess(rep, now)
	if rep.Assessment.Level != "review" {
		t.Fatalf("review: %+v %+v", rep.Assessment, rep.Signals)
	}
	joined := ""
	for _, s := range rep.Signals {
		joined += s.Text + "\n"
	}
	for _, want := range []string{"not in the knowledge base", "temporary/download location", "beacon-like", "contacted only by this program", "uncommon port 8081"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing signal %q in:\n%s", want, joined)
		}
	}
	// Trusted destinations never raise signals.
	rep = &Report{Program: Program{Name: "chrome", Known: Lookup("chrome", ""), FirstSeen: &old},
		Destinations: []Destination{{Dst: "1.2.3.4", Port: 4444, Proto: "tcp", Lists: []string{"feodo"}, Trusted: "1.2.3.4"}}}
	Assess(rep, now)
	if rep.Assessment.Level != "expected" {
		t.Errorf("trusted peer should be ignored: %+v", rep.Signals)
	}
}

func TestAssessUnknownOwner(t *testing.T) {
	rep := &Report{Program: Program{Name: "(unknown process)", OS: "linux"}, Destinations: []Destination{{Dst: "8.8.8.8", Port: 53, Proto: "udp", Infra: Classify("Google", "", "", ""), OtherHosts: 2}}}
	Assess(rep, time.Now())
	if rep.Assessment.Level != "expected" || len(rep.Signals) != 1 || !strings.Contains(rep.Signals[0].Text, "could not resolve") || !strings.Contains(rep.Signals[0].Text, "eBPF") {
		t.Fatalf("unknown owner: %+v %+v", rep.Assessment, rep.Signals)
	}
}

func TestVerifyCommands(t *testing.T) {
	rep := &Report{Program: Program{OS: "windows", Exe: `C:\x\svchost.exe`, Pids: []int{1234}, Known: Lookup("svchost.exe", "")}, Destinations: []Destination{{Dst: "8.8.8.8"}}}
	cmds := strings.Join(verifyCommands(rep), "\n")
	for _, want := range []string{"Get-Process -Id 1234", "Get-AuthenticodeSignature", "netstat -bano | findstr 1234", "Resolve-DnsName 8.8.8.8", `tasklist /svc /fi "pid eq 1234"`} {
		if !strings.Contains(cmds, want) {
			t.Errorf("windows verify missing %q:\n%s", want, cmds)
		}
	}
	rep = &Report{Program: Program{OS: "linux", Exe: "/usr/bin/pasta.avx2", Container: "web", Pids: []int{7}, Known: Lookup("pasta.avx2", "")}}
	cmds = strings.Join(verifyCommands(rep), "\n")
	for _, want := range []string{"ps -o pid,user,etime,cmd -p 7", "readlink /proc/7/exe", "podman exec web ss -tn", "podman ps --all"} {
		if !strings.Contains(cmds, want) {
			t.Errorf("linux verify missing %q:\n%s", want, cmds)
		}
	}
}
