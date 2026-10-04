-- github.com/kararnab/iam/pgstore schema: sessions and invites, version 1.
--
-- For applications that implement iam.UserStore over their own tables.
-- Run with pgstore.MigrateSessions, or copy into your own migration tool.
-- The same statements are part of the full set (pgstore.Migrations).
-- Secrets are never stored: token_hash columns hold SHA-256 hashes.

-- Sessions for both modes. subject_id is deliberately not a foreign key,
-- so the session table also works with an application-owned user table.
CREATE TABLE iam_sessions (
    id           TEXT PRIMARY KEY,
    subject_id   TEXT        NOT NULL,
    mode         TEXT        NOT NULL CHECK (mode IN ('cookie', 'bearer')),
    token_hash   BYTEA       NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_at   TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    attrs        JSONB       NOT NULL DEFAULT '{}'
);
CREATE INDEX iam_sessions_subject_idx ON iam_sessions (subject_id);
CREATE INDEX iam_sessions_expires_idx ON iam_sessions (expires_at);

-- Refresh tokens / session secrets that were rotated away, for reuse detection.
CREATE TABLE iam_rotated_tokens (
    token_hash BYTEA PRIMARY KEY CHECK (length(token_hash) = 32),
    session_id TEXT        NOT NULL REFERENCES iam_sessions (id) ON DELETE CASCADE,
    rotated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX iam_rotated_tokens_session_idx ON iam_rotated_tokens (session_id);

-- Single-use sign-up invites.
CREATE TABLE iam_invites (
    id         TEXT PRIMARY KEY,
    token_hash BYTEA       NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    email      TEXT        NOT NULL DEFAULT '',
    roles      TEXT[]      NOT NULL DEFAULT '{}',
    created_by TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    used_by    TEXT        NOT NULL DEFAULT ''
);
