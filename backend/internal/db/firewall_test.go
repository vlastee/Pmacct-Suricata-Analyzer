package db

import "testing"

func TestSummarizeBlocksAndRuleName(t *testing.T) {
	a, b := int64(1000000103), int64(1788059119)
	hits := []FirewallRuleHit{
		{Action: "block", Outbound: true, Tracker: &b, Iface: "vtnet1", Packets: 3, Attempts: 3},
		{Action: "block", Outbound: true, Tracker: &a, Label: "Default deny (IPv4)", Iface: "vtnet1", Packets: 9, Attempts: 6},
		{Action: "block", Outbound: false, Tracker: &a, Packets: 50}, // inbound: not counted
		{Action: "pass", Outbound: true, Tracker: &b, Packets: 7},    // passed: not counted
	}
	pk, at, rules := SummarizeBlocks(hits)
	if pk != 12 || at != 9 || len(rules) != 2 || rules[0] != `"Default deny (IPv4)" (tracker 1000000103) on vtnet1` || rules[1] != "rule tracker 1788059119 on vtnet1" {
		t.Errorf("summarize: %d %d %q", pk, at, rules)
	}
	labels := map[int64]string{a: "Default deny (IPv4)"}
	if RuleName(labels, &a) != `"Default deny (IPv4)" (tracker 1000000103)` || RuleName(labels, &b) != "rule tracker 1788059119" || RuleName(labels, nil) != "unknown rule" {
		t.Error("rule names")
	}
}
