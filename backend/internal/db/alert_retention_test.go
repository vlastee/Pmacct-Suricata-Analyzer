package db

import "testing"

func TestAlertRetentionValidate(t *testing.T) {
	r := DefaultAlertRetention()
	if err := r.Validate(); err != nil || r.DeleteResolvedDays[SevInfo] != 7 || r.DeleteResolvedDays[SevCritical] != 60 || r.AutoResolveDays != 7 {
		t.Fatalf("defaults: %+v %v", r, err)
	}
	partial := AlertRetention{AutoResolveDays: 3, DeleteResolvedDays: map[string]int{SevInfo: 0}}
	if err := partial.Validate(); err != nil || partial.DeleteResolvedDays[SevWarning] != 60 || partial.DeleteResolvedDays[SevInfo] != 0 {
		t.Fatalf("partial should fill defaults: %+v %v", partial, err)
	}
	for _, bad := range []AlertRetention{
		{AutoResolveDays: 0},
		{AutoResolveDays: 400},
		{AutoResolveDays: 7, DeleteResolvedDays: map[string]int{"urgent": 1}},
		{AutoResolveDays: 7, DeleteResolvedDays: map[string]int{SevInfo: -1}},
		{AutoResolveDays: 7, DeleteResolvedDays: map[string]int{SevCritical: 5000}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v should be rejected", bad)
		}
	}
}
