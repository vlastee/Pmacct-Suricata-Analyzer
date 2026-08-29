package db

import (
	"net/netip"
	"testing"
)

func TestValidateRuleSQL(t *testing.T) {
	for _, ok := range []string{"SELECT 1", "  with x as (select 1) select * from x", "WITH a AS (SELECT 1)\nSELECT host FROM a"} {
		if err := ValidateRuleSQL(ok); err != nil {
			t.Errorf("%q should be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "DELETE FROM acct", "SELECT 1; SELECT 2", "INSERT INTO x SELECT 1", "-- c\nSELECT 1"} {
		if err := ValidateRuleSQL(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestRuleValueCoercion(t *testing.T) {
	if ipString(netip.MustParsePrefix("10.0.0.5/32")) != "10.0.0.5" || ipString(netip.MustParseAddr("::ffff:1.2.3.4")) != "1.2.3.4" ||
		ipString("192.168.1.9/24") != "192.168.1.9" || ipString(nil) != "" {
		t.Error("ipString")
	}
	if toInt(int32(443)) != 443 || toInt(int64(8)) != 8 || toInt("22") != 22 || toInt(nil) != 0 || toInt(3.0) != 3 {
		t.Error("toInt")
	}
	if d := detailsOf(`{"bytes": 5}`); d["bytes"] != 5.0 {
		t.Errorf("detailsOf json string: %v", d)
	}
	if d := detailsOf(map[string]any{"a": 1}); d["a"] != 1 {
		t.Errorf("detailsOf map: %v", d)
	}
	if d := detailsOf("plain"); d["details"] != "plain" {
		t.Errorf("detailsOf plain: %v", d)
	}
}
