-- github.com/kararnab/iam/pgstore schema, version 5: rate limits.
--
-- Failure counters for pgstore.Limiter (package ratelimit), shared by
-- every instance. Keys are the limiter's opaque keys; rows whose window
-- and block are both over are dead and removed by Limiter.PurgeExpired.

-- One row per throttled key.
CREATE TABLE iam_rate_limits (
    key           TEXT PRIMARY KEY,
    failures      INTEGER     NOT NULL CHECK (failures >= 0),
    window_start  TIMESTAMPTZ NOT NULL,
    blocked_until TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX iam_rate_limits_expires_idx ON iam_rate_limits (expires_at);
