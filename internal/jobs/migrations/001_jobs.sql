-- Opt-in prototype; does not modify existing application tables.
CREATE TABLE IF NOT EXISTS m4_jobs (
 id text PRIMARY KEY, state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','succeeded','failed','cancelling','cancelled')),
 attempt integer NOT NULL DEFAULT 0 CHECK(attempt >= 0), max_attempts integer NOT NULL CHECK(max_attempts BETWEEN 1 AND 100),
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(), lease_until timestamptz, worker text,
 artifact_path text, artifact_sha256 text, last_error text,
 CHECK ((state IN ('running','cancelling')) = (lease_until IS NOT NULL)),
 CHECK ((state = 'succeeded') = (artifact_path IS NOT NULL AND artifact_sha256 IS NOT NULL)),
 CHECK (artifact_sha256 IS NULL OR artifact_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS m4_jobs_claim ON m4_jobs(available_at,id) WHERE state IN ('queued','running');
