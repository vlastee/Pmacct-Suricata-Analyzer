-- Per-agent self-update switch (the global toggle lives in settings["agent_retention"]).
ALTER TABLE agents ADD COLUMN IF NOT EXISTS auto_update boolean NOT NULL DEFAULT true;
