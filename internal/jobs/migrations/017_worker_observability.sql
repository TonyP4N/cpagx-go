-- Ephemeral operational observations, not job authority or business identity.
-- Backup restore must clear these rows before serving; migrated old databases
-- correctly have no online worker until an authenticated fresh observation.
CREATE TABLE IF NOT EXISTS m4_worker_observations (
 worker text PRIMARY KEY CHECK (length(worker) BETWEEN 1 AND 100),
 last_seen timestamptz NOT NULL DEFAULT clock_timestamp(),
 last_kind text NOT NULL CHECK (last_kind IN ('claim','heartbeat'))
);
CREATE INDEX IF NOT EXISTS m4_worker_observations_seen ON m4_worker_observations(last_seen);
