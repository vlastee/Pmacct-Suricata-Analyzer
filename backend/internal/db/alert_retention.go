package db

import (
	"context"
	"fmt"
	"time"
)

// AlertRetention is the user-configurable alert lifecycle (settings["alert_retention"]):
// open/acked alerts auto-resolve after AutoResolveDays without recurring, and resolved alerts
// are deleted after DeleteResolvedDays[severity] (0 = keep forever).
type AlertRetention struct {
	AutoResolveDays    int            `json:"auto_resolve_days"`
	DeleteResolvedDays map[string]int `json:"delete_resolved_days"`
}

// DefaultAlertRetention: a week of silence resolves; info is short-lived, the rest is kept two months.
func DefaultAlertRetention() AlertRetention {
	return AlertRetention{AutoResolveDays: 7, DeleteResolvedDays: map[string]int{SevInfo: 7, SevWarning: 60, SevCritical: 60}}
}

// Validate checks ranges and fills missing severities with the defaults.
func (r *AlertRetention) Validate() error {
	if r.AutoResolveDays < 1 || r.AutoResolveDays > 365 {
		return fmt.Errorf("auto_resolve_days must be between 1 and 365")
	}
	def := DefaultAlertRetention().DeleteResolvedDays
	if r.DeleteResolvedDays == nil {
		r.DeleteResolvedDays = map[string]int{}
	}
	for sev := range r.DeleteResolvedDays {
		if SeverityRank(sev) == 0 {
			return fmt.Errorf("unknown severity %q", sev)
		}
	}
	for sev, d := range def {
		v, ok := r.DeleteResolvedDays[sev]
		if !ok {
			r.DeleteResolvedDays[sev] = d
			continue
		}
		if v < 0 || v > 3650 {
			return fmt.Errorf("delete_resolved_days.%s must be between 0 (keep forever) and 3650", sev)
		}
	}
	return nil
}

// AutoResolveAfter is AutoResolveDays as a duration.
func (r AlertRetention) AutoResolveAfter() time.Duration {
	return time.Duration(r.AutoResolveDays) * 24 * time.Hour
}

// GetAlertRetention returns the stored settings or the defaults.
func (d *DB) GetAlertRetention(ctx context.Context) (AlertRetention, error) {
	r := DefaultAlertRetention()
	if ok, err := d.GetSetting(ctx, "alert_retention", &r); err != nil {
		return DefaultAlertRetention(), err
	} else if !ok {
		return DefaultAlertRetention(), nil
	}
	if err := r.Validate(); err != nil {
		return DefaultAlertRetention(), nil
	}
	return r, nil
}

// SetAlertRetention validates and persists.
func (d *DB) SetAlertRetention(ctx context.Context, r AlertRetention) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return d.SetSetting(ctx, "alert_retention", r)
}

// PruneResolvedAlerts deletes resolved alerts older than each severity's retention and returns
// how many were removed per severity.
func (d *DB) PruneResolvedAlerts(ctx context.Context, r AlertRetention) (map[string]int64, error) {
	out := map[string]int64{}
	for sev, days := range r.DeleteResolvedDays {
		if days <= 0 {
			continue
		}
		tag, err := d.Pool.Exec(ctx, `DELETE FROM alerts WHERE state = 'resolved' AND severity = $1 AND resolved_at < now() - ($2::int * interval '1 day')`, sev, days)
		if err != nil {
			return out, err
		}
		if n := tag.RowsAffected(); n > 0 {
			out[sev] = n
		}
	}
	return out, nil
}
