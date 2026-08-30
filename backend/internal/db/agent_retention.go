package db

import (
	"context"
	"fmt"
	"time"
)

// AgentRetention controls how long endpoint-agent data is kept (settings["agent_retention"]).
type AgentRetention struct {
	ConnDays       int  `json:"conn_days"`        // per-minute connection aggregates; 0 = keep forever
	StaleAgentDays int  `json:"stale_agent_days"` // delete agents (and their data) silent this long; 0 = never
	AutoUpdate     bool `json:"auto_update"`      // let agents replace themselves with the image's newer build
}

// DefaultAgentRetention keeps two weeks of attribution data, never forgets agents, and lets
// agents update themselves from the analyzer's build.
func DefaultAgentRetention() AgentRetention { return AgentRetention{ConnDays: 15, AutoUpdate: true} }

func (r AgentRetention) Validate() error {
	if r.ConnDays < 0 || r.ConnDays > 3650 {
		return fmt.Errorf("conn_days must be between 0 (keep forever) and 3650")
	}
	if r.StaleAgentDays < 0 || r.StaleAgentDays > 3650 {
		return fmt.Errorf("stale_agent_days must be between 0 (never) and 3650")
	}
	return nil
}

func (d *DB) GetAgentRetention(ctx context.Context) (AgentRetention, error) {
	r := DefaultAgentRetention()
	if ok, err := d.GetSetting(ctx, "agent_retention", &r); err != nil {
		return DefaultAgentRetention(), err
	} else if !ok || r.Validate() != nil {
		return DefaultAgentRetention(), nil
	}
	return r, nil
}

func (d *DB) SetAgentRetention(ctx context.Context, r AgentRetention) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return d.SetSetting(ctx, "agent_retention", r)
}

// PruneAgentData applies the retention: old aggregates, then agents silent for too long
// (their remaining data goes with them). Returns rows and agents removed.
func (d *DB) PruneAgentData(ctx context.Context, r AgentRetention) (conns, agents int64, err error) {
	if r.ConnDays > 0 {
		conns, err = d.PruneEndpointConns(ctx, time.Duration(r.ConnDays)*24*time.Hour)
		if err != nil {
			return 0, 0, err
		}
	}
	if r.StaleAgentDays > 0 {
		tag, err := d.Pool.Exec(ctx, `DELETE FROM agents WHERE COALESCE(last_seen, enrolled_at) < now() - ($1::int * interval '1 day')`, r.StaleAgentDays)
		if err != nil {
			return conns, 0, err
		}
		agents = tag.RowsAffected()
	}
	return conns, agents, nil
}
