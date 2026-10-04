-- github.com/kararnab/iam/pgstore schema, version 4: passkeys.
--
-- WebAuthn credentials (package passkey). Only public keys are stored.
-- subject_id is deliberately not a foreign key, like iam_sessions.

-- Registered WebAuthn credentials.
CREATE TABLE iam_passkeys (
    id                 BYTEA PRIMARY KEY,
    subject_id         TEXT        NOT NULL,
    name               TEXT        NOT NULL DEFAULT '',
    public_key         BYTEA       NOT NULL,
    attestation_type   TEXT        NOT NULL DEFAULT '',
    attestation_format TEXT        NOT NULL DEFAULT '',
    aaguid             BYTEA,
    transports         TEXT[]      NOT NULL DEFAULT '{}',
    sign_count         BIGINT      NOT NULL DEFAULT 0,
    user_present       BOOLEAN     NOT NULL DEFAULT FALSE,
    user_verified      BOOLEAN     NOT NULL DEFAULT FALSE,
    backup_eligible    BOOLEAN     NOT NULL DEFAULT FALSE,
    backup_state       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ NOT NULL,
    last_used_at       TIMESTAMPTZ
);
CREATE INDEX iam_passkeys_subject_idx ON iam_passkeys (subject_id, created_at);
