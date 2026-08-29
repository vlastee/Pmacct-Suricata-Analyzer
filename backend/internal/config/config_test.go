package config

import (
	"net/netip"
	"testing"
)

func TestParsePrefixesAndIsLocal(t *testing.T) {
	ps, err := ParsePrefixes("10.0.0.0/8, 174.54.200.232 ,fc00::/7")
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 3 {
		t.Fatalf("want 3 prefixes, got %d", len(ps))
	}
	c := &Config{LocalNetworks: ps}
	for ip, want := range map[string]bool{"10.1.2.3": true, "174.54.200.232": true, "174.54.200.233": false, "8.8.8.8": false, "fd00::1": true} {
		if got := c.IsLocal(netip.MustParseAddr(ip)); got != want {
			t.Errorf("IsLocal(%s)=%v want %v", ip, got, want)
		}
	}
	if _, err := ParsePrefixes("not-an-ip"); err == nil {
		t.Error("expected error for garbage input")
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("ENRICH_INTERVAL", "90s")
	t.Setenv("ENRICH_ENABLED", "false")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.EnrichInterval.Seconds() != 90 || c.EnrichEnabled {
		t.Errorf("env not applied: %+v", c)
	}
	if len(c.LocalNetworks) == 0 {
		t.Error("default local networks empty")
	}
	t.Setenv("ENRICH_INTERVAL", "bogus")
	if _, err := Load(); err == nil {
		t.Error("expected error for bad duration")
	}
}
