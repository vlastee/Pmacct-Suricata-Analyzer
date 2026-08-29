-- Authentication, sessions, brute-force tracking and IP access control.

CREATE TABLE IF NOT EXISTS users (
    id                   bigserial PRIMARY KEY,
    username             text UNIQUE NOT NULL,
    password_hash        text NOT NULL,
    is_admin             boolean NOT NULL DEFAULT true,
    must_change_password boolean NOT NULL DEFAULT false,
    disabled             boolean NOT NULL DEFAULT false,
    created_at           timestamptz NOT NULL DEFAULT now(),
    last_login           timestamptz,
    last_login_ip        inet
);

CREATE TABLE IF NOT EXISTS sessions (
    token      text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    ip         inet,
    user_agent text
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS login_attempts (
    id         bigserial PRIMARY KEY,
    ts         timestamptz NOT NULL DEFAULT now(),
    ip         inet,
    username   text,
    success    boolean NOT NULL,
    reason     text,
    user_agent text
);
CREATE INDEX IF NOT EXISTS login_attempts_ts_idx ON login_attempts(ts DESC);
CREATE INDEX IF NOT EXISTS login_attempts_ip_idx ON login_attempts(ip, ts DESC);

-- Manual allow/deny plus temporary auto lockouts from brute-force protection.
CREATE TABLE IF NOT EXISTS ip_access (
    net        cidr PRIMARY KEY,
    action     text NOT NULL,                     -- allow | deny
    source     text NOT NULL DEFAULT 'manual',    -- manual | auto
    note       text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz                        -- NULL = permanent
);
CREATE INDEX IF NOT EXISTS ip_access_gist ON ip_access USING gist (net inet_ops);
