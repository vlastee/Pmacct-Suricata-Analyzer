package db

import "testing"

func TestNormalizeExclusion(t *testing.T) {
	cases := map[string][2]string{
		" 10.0.0.5 ":         {"10.0.0.5", "ip"},
		"::ffff:1.2.3.4":     {"1.2.3.4", "ip"},
		"203.0.113.7/32":     {"203.0.113.7", "ip"},
		"203.0.113.77/24":    {"203.0.113.0/24", "cidr"},
		"*.Anthropic.COM":    {"*.anthropic.com", "name"},
		"discord.com.":       {"discord.com", "name"},
		"api-1_x.example.io": {"api-1_x.example.io", "name"},
	}
	for in, want := range cases {
		norm, kind, err := NormalizeExclusion(in)
		if err != nil || norm != want[0] || kind != want[1] {
			t.Errorf("%q -> %q %q %v, want %v", in, norm, kind, err, want)
		}
	}
	for _, bad := range []string{"", "*", "*.", "bad host", "http://x.com", "a;b"} {
		if _, _, err := NormalizeExclusion(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestExclusionSetMatch(t *testing.T) {
	set := NewExclusionSet([]Exclusion{
		{Pattern: "10.0.0.5", Kind: "ip"},
		{Pattern: "203.0.113.0/24", Kind: "cidr"},
		{Pattern: "*.anthropic.com", Kind: "name"},
		{Pattern: "discord.com", Kind: "name"},
	})
	if set.Empty() || !set.HasNames() {
		t.Fatal("set flags")
	}
	if p, ok := set.MatchIP("10.0.0.5"); !ok || p != "10.0.0.5" {
		t.Error("exact ip")
	}
	if _, ok := set.MatchIP("10.0.0.50"); ok {
		t.Error("10.0.0.50 must not match 10.0.0.5")
	}
	if p, ok := set.MatchIP("203.0.113.200"); !ok || p != "203.0.113.0/24" {
		t.Error("cidr")
	}
	if p, ok := set.Match("160.79.104.10", []string{"API.anthropic.com."}); !ok || p != "*.anthropic.com" {
		t.Error("name glob")
	}
	if _, ok := set.Match("1.2.3.4", []string{"anthropic.com"}); ok {
		t.Error("*.anthropic.com must not match the bare apex")
	}
	if p, ok := set.Match("1.2.3.4", []string{"cdn.example", "discord.com"}); !ok || p != "discord.com" {
		t.Error("exact name")
	}
	if _, ok := set.Match("1.2.3.4", []string{"notdiscord.com", "discord.com.evil"}); ok {
		t.Error("exact name must be anchored")
	}
	if _, ok := set.Match("", nil); ok {
		t.Error("empty ip")
	}
	var nilSet *ExclusionSet
	if !nilSet.Empty() {
		t.Error("nil set is empty")
	}
}
