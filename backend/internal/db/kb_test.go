package db

import "testing"

func TestKBMatching(t *testing.T) {
	entries := []KBEntry{
		{ID: 1, MatchKind: "name", Pattern: "pmacct-*", Title: "our agent"},
		{ID: 2, MatchKind: "path", Pattern: "/app/*/server", Title: "analyzer container"},
		{ID: 3, MatchKind: "hash", Pattern: "ab" + "cd" + "0000000000000000000000000000000000000000000000000000000000000000"[4:], Title: "pinned build"},
		{ID: 4, MatchKind: "name", Pattern: "server", Title: "generic"},
	}
	for i := range entries {
		if err := entries[i].Normalize(); err != nil {
			t.Fatalf("normalize %d: %v", i, err)
		}
	}
	if m := MatchKB(entries, "pmacct-agent", "/usr/local/bin/pmacct-agent", nil); m == nil || m.ID != 1 {
		t.Errorf("name glob: %+v", m)
	}
	if m := MatchKB(entries, "server", "/app/x/server", nil); m == nil || m.ID != 2 {
		t.Errorf("path beats name: %+v", m)
	}
	if m := MatchKB(entries, "server", "/opt/server", nil); m == nil || m.ID != 4 {
		t.Errorf("name fallback: %+v", m)
	}
	if m := MatchKB(entries, "whatever", "/x/y", []string{entries[2].Pattern}); m == nil || m.ID != 3 {
		t.Errorf("hash wins: %+v", m)
	}
	if m := MatchKB(entries, "chrome.exe", `C:\Program Files\chrome.exe`, nil); m != nil {
		t.Errorf("no match expected: %+v", m)
	}
	// Windows paths and case are normalised.
	win := KBEntry{MatchKind: "path", Pattern: `C:\Users\*\AppData\Local\Temp\*.exe`, Title: "temp"}
	_ = win.Normalize()
	if !win.Matches("x.exe", `C:\Users\Petro\AppData\Local\Temp\Evil.EXE`, nil) {
		t.Error("windows path glob")
	}
	for _, bad := range []KBEntry{{MatchKind: "name", Pattern: "*", Title: "t"}, {MatchKind: "hash", Pattern: "zz", Title: "t"}, {MatchKind: "name", Pattern: "a/b", Title: "t"}, {MatchKind: "name", Pattern: "x", Title: ""}, {MatchKind: "name", Pattern: "x", Title: "t", Risk: "bad"}, {MatchKind: "glob", Pattern: "x", Title: "t"}} {
		if err := bad.Normalize(); err == nil {
			t.Errorf("%+v should be rejected", bad)
		}
	}
}
