-- github.com/kararnab/iam/pgstore schema: users, version 1.
--
-- Subjects, linked identities and password hashes, for pgstore.Users.
-- Run with pgstore.MigrateUsers, or copy into your own migration tool.
-- The same statements are part of the full set (pgstore.Migrations).

-- Subjects (users). Applications with their own user table can implement
-- iam.UserStore themselves and use only the session and invite tables.
CREATE TABLE iam_subjects (
    id         TEXT PRIMARY KEY,
    roles      TEXT[]      NOT NULL DEFAULT '{}',
    attrs      JSONB       NOT NULL DEFAULT '{}',
    disabled   BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Provider identities linked to subjects (one subject, many identities).
CREATE TABLE iam_identities (
    provider    TEXT        NOT NULL,
    provider_id TEXT        NOT NULL,
    subject_id  TEXT        NOT NULL REFERENCES iam_subjects (id) ON DELETE CASCADE,
    email       TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, provider_id)
);
CREATE INDEX iam_identities_subject_idx ON iam_identities (subject_id);

-- Password hashes (argon2id PHC strings, or legacy bcrypt) by login.
CREATE TABLE iam_credentials (
    login         TEXT PRIMARY KEY,
    password_hash TEXT        NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
