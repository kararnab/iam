-- github.com/kararnab/iam/pgstore schema, version 2: one-time tokens.
--
-- Password-reset and email-verification tokens (package onetime).
-- subject_id is deliberately not a foreign key, like iam_sessions.

-- Single-use tokens for account actions.
CREATE TABLE iam_one_time_tokens (
    id         TEXT PRIMARY KEY,
    token_hash BYTEA       NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    purpose    TEXT        NOT NULL CHECK (purpose IN ('password_reset', 'email_verification')),
    subject_id TEXT        NOT NULL,
    login      TEXT        NOT NULL DEFAULT '',
    email      TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);
CREATE INDEX iam_one_time_tokens_subject_idx ON iam_one_time_tokens (subject_id, purpose);
CREATE INDEX iam_one_time_tokens_expires_idx ON iam_one_time_tokens (expires_at);
