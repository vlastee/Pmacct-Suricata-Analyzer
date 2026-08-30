package db

import "testing"

func TestAgentRetentionValidate(t *testing.T) {
	r := DefaultAgentRetention()
	if err := r.Validate(); err != nil || r.ConnDays != 15 || r.StaleAgentDays != 0 {
		t.Fatalf("defaults: %+v %v", r, err)
	}
	for _, bad := range []AgentRetention{{ConnDays: -1}, {ConnDays: 4000}, {StaleAgentDays: -5}, {ConnDays: 15, StaleAgentDays: 9999}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v should be rejected", bad)
		}
	}
}
