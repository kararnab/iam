-- github.com/kararnab/iam/pgstore schema, version 3: TOTP factors.
--
-- One TOTP factor per subject (package mfa). secret is sealed by IAM
-- (AES-GCM, iam.MFAConfig.Key); recovery_codes holds SHA-256 hashes.
-- subject_id is deliberately not a foreign key, like iam_sessions.

-- TOTP factors.
CREATE TABLE iam_mfa_totp (
    subject_id     TEXT PRIMARY KEY,
    secret         BYTEA       NOT NULL,
    confirmed      BOOLEAN     NOT NULL DEFAULT FALSE,
    last_step      BIGINT      NOT NULL DEFAULT 0,
    recovery_codes BYTEA[]     NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL
);
