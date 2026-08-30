-- Container attribution for agent-reported connections (own cgroup, or the container behind a
-- pasta/slirp4netns proxy). Part of the aggregate key.
ALTER TABLE endpoint_conns ADD COLUMN IF NOT EXISTS container text NOT NULL DEFAULT '';
DO $$
DECLARE c text;
BEGIN
  SELECT conname INTO c FROM pg_constraint WHERE conrelid = 'endpoint_conns'::regclass AND contype = 'u' LIMIT 1;
  IF c IS NOT NULL THEN
    EXECUTE format('ALTER TABLE endpoint_conns DROP CONSTRAINT %I', c);
  END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS endpoint_conns_key ON endpoint_conns (agent_id, minute, host, proto, dst, dst_port, exe, "user", container);
