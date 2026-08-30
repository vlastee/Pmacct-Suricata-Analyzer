package explain

import (
	"strings"
	"testing"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

func signalsText(rep *Report) string {
	var sb strings.Builder
	for _, s := range rep.Signals {
		sb.WriteString(s.Level + ": " + s.Text + "\n")
	}
	return sb.String()
}

func TestAssessIdentity(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	old := now.Add(-30 * 24 * time.Hour)
	yes, no := true, false
	zero, forty, seventy := 0, 40, 70

	// Package-managed, manifest OK, VT clean: expected, informative signals only.
	rep := &Report{Program: Program{Name: "curl", Exe: "/usr/bin/curl", User: "petro", FirstSeen: &old,
		Identity: &db.ProgramIdentity{Origin: "dpkg", Package: "curl", PackageVersion: "8.18.0-1ubuntu2.4", Verified: &yes},
		File:     &db.FileIntel{VT: db.FileVT{Status: "ok", Malicious: &zero, Undetected: &seventy}, MHR: db.FileMHR{Status: "clean"}}},
		Destinations: []Destination{{Dst: "104.16.1.1", Port: 443, Proto: "tcp", Hostname: "example.org", Infra: Classify("Cloudflare", "", "", ""), OtherHosts: 2}}}
	Assess(rep, now)
	txt := signalsText(rep)
	if rep.Assessment.Level != "expected" || !strings.Contains(txt, "matches the package manifest") || !strings.Contains(txt, "VirusTotal: 0 of 70 engines") {
		t.Fatalf("packaged+clean: %s %s", rep.Assessment.Level, txt)
	}

	// Manifest mismatch is critical on its own; MHR listing too.
	rep = &Report{Program: Program{Name: "sshd", Exe: "/usr/sbin/sshd", Identity: &db.ProgramIdentity{Origin: "dpkg", Package: "openssh-server", Verified: &no},
		File: &db.FileIntel{VT: db.FileVT{Status: "unknown"}, MHR: db.FileMHR{Status: "listed", Detection: &forty}}}}
	Assess(rep, now)
	txt = signalsText(rep)
	if rep.Assessment.Level != "suspicious" || !strings.Contains(txt, "critical: The file differs from what package openssh-server") || !strings.Contains(txt, "Malware Hash Registry lists this file") || !strings.Contains(txt, "40% of AV engines") {
		t.Fatalf("mismatch: %s %s", rep.Assessment.Level, txt)
	}

	// Windows: unsigned + never seen by VirusTotal → review, and the VT-unknown signal is a warning.
	rep = &Report{Program: Program{Name: "helper.exe", Exe: `C:\Users\petro\AppData\Local\Foo\helper.exe`, OS: "windows",
		Identity: &db.ProgramIdentity{Origin: "user-install", Signature: "unsigned", Company: "Foo Inc"},
		File:     &db.FileIntel{VT: db.FileVT{Status: "unknown"}}}}
	Assess(rep, now)
	txt = signalsText(rep)
	if rep.Assessment.Level != "review" || !strings.Contains(txt, "warn: Not digitally signed even though the version resource names Foo Inc") || !strings.Contains(txt, "warn: This exact file has never been submitted") {
		t.Fatalf("unsigned: %s %s", rep.Assessment.Level, txt)
	}

	// Windows: catalog-signed by Microsoft, VT known and clean → expected.
	rep = &Report{Program: Program{Name: "svchost.exe", Exe: `C:\Windows\System32\svchost.exe`, OS: "windows", FirstSeen: &old, Known: Lookup("svchost.exe", ""),
		Identity: &db.ProgramIdentity{Origin: "windows", Signature: "valid", Signer: "Microsoft Windows", Note: "catalog Microsoft-Windows-Client.cat"},
		File:     &db.FileIntel{VT: db.FileVT{Status: "ok", Malicious: &zero, Harmless: &seventy}}},
		Destinations: []Destination{{Dst: "13.107.4.50", Port: 443, Proto: "tcp", Hostname: "ctldl.windowsupdate.com", Infra: Classify("Microsoft", "", "", ""), OtherHosts: 3}}}
	Assess(rep, now)
	txt = signalsText(rep)
	if rep.Assessment.Level != "expected" || !strings.Contains(txt, "signed by Microsoft Windows (Windows security catalog)") {
		t.Fatalf("catalog signed: %s %s", rep.Assessment.Level, txt)
	}

	// Invalid signature and VT detections: suspicious with critical signals first.
	rep = &Report{Program: Program{Name: "update.exe", Exe: `C:\ProgramData\x\update.exe`, OS: "windows",
		Identity: &db.ProgramIdentity{Origin: "programdata", Signature: "invalid", Signer: "Contoso"},
		File:     &db.FileIntel{VT: db.FileVT{Status: "ok", Malicious: &forty, Undetected: &zero, Label: "trojan.agent/redline"}}}}
	Assess(rep, now)
	if rep.Assessment.Level != "suspicious" || rep.Signals[0].Level != "critical" || !strings.Contains(signalsText(rep), "40 of 40 VirusTotal engines flag this file as malicious (trojan.agent/redline)") {
		t.Fatalf("invalid+vt: %s %s", rep.Assessment.Level, signalsText(rep))
	}

	// No package owns a file under /usr → warning; a file in a container is only informational.
	rep = &Report{Program: Program{Name: "x", Exe: "/usr/bin/x", Identity: &db.ProgramIdentity{Origin: "unpackaged"}}}
	Assess(rep, now)
	if rep.Assessment.Level != "review" || !strings.Contains(signalsText(rep), "No package owns this file") {
		t.Fatalf("unpackaged: %s %s", rep.Assessment.Level, signalsText(rep))
	}
	rep = &Report{Program: Program{Name: "server", Exe: "/app/server", Container: "web-app", Identity: &db.ProgramIdentity{Origin: "container", Package: "web-app"}}}
	Assess(rep, now)
	if !strings.Contains(signalsText(rep), "info: Runs inside container web-app") {
		t.Fatalf("container: %s", signalsText(rep))
	}
}

func TestLOLBinKnowledge(t *testing.T) {
	now := time.Now()
	l := &db.LOLBin{Source: "lolbas", Name: "certutil", Display: "Certutil.exe", Description: "Windows binary used for handling certificates.", Functions: []string{"Decode", "Download", "Encode"}, URL: "https://lolbas-project.github.io/lolbas/Binaries/Certutil/"}
	k := KnownFromLOLBin(l)
	if k.Risk != "lolbin" || k.Category != "lolbin" || !strings.Contains(k.Title, "LOLBAS") || !strings.Contains(k.Description, "Abusable for: Decode, Download, Encode") {
		t.Fatalf("known from lolbin: %+v", k)
	}
	// Catalogue-only knowledge: one warning naming the functions.
	rep := &Report{Program: Program{Name: "certutil.exe", Exe: `C:\Windows\System32\certutil.exe`, OS: "windows", Known: k, KnownSource: "lolbas", LOLBin: l}}
	Assess(rep, now)
	txt := signalsText(rep)
	if rep.Assessment.Level != "review" || !strings.Contains(txt, "listed by LOLBAS as abusable for Decode, Download, Encode") || strings.Count(txt, "LOLBAS") != 1 {
		t.Fatalf("lolbin signal: %s %s", rep.Assessment.Level, txt)
	}
	// A built-in entry with a different risk still gets the catalogue warning once.
	rep = &Report{Program: Program{Name: "curl", Exe: "/usr/bin/curl", Known: Lookup("curl", ""), KnownSource: "builtin", LOLBin: &db.LOLBin{Source: "gtfobins", Name: "curl", Functions: []string{"File download", "File upload"}}}}
	Assess(rep, now)
	txt = signalsText(rep)
	if strings.Count(txt, "GTFOBins") != 1 || !strings.Contains(txt, "abusable for File download, File upload") {
		t.Fatalf("builtin + catalogue: %s", txt)
	}
}

func TestVerifyCommandsIdentity(t *testing.T) {
	rep := &Report{Program: Program{Name: "curl", Exe: "/usr/bin/curl", OS: "linux", Pids: []int{42}, Identity: &db.ProgramIdentity{Origin: "dpkg", Package: "curl"}}}
	cmds := strings.Join(verifyCommands(rep), "\n")
	if !strings.Contains(cmds, "dpkg -S '/usr/bin/curl' && dpkg -V curl") {
		t.Errorf("dpkg verify: %s", cmds)
	}
	rep = &Report{Program: Program{Name: "x", Exe: "/opt/x/x", OS: "linux", Identity: &db.ProgramIdentity{Origin: "opt"}}}
	cmds = strings.Join(verifyCommands(rep), "\n")
	if strings.Contains(cmds, "dpkg -V") {
		t.Errorf("no package verify for unowned files: %s", cmds)
	}
	rep = &Report{Program: Program{Name: "a.exe", Exe: `C:\x\a.exe`, OS: "windows"}}
	cmds = strings.Join(verifyCommands(rep), "\n")
	if !strings.Contains(cmds, "VersionInfo | Format-List CompanyName") {
		t.Errorf("windows version info: %s", cmds)
	}
}
