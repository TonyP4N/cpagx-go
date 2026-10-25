CREATE TABLE IF NOT EXISTS m4_job_attempts (
 job_id text NOT NULL REFERENCES m4_jobs(id) ON DELETE CASCADE,
 attempt integer NOT NULL CHECK(attempt>0), worker text NOT NULL, attempt_token text NOT NULL,
 claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(), location text NOT NULL DEFAULT 'legacy-process-group',
 container_id text NOT NULL DEFAULT '', exited_at timestamptz, exit_receipt jsonb,
 publication_state text NOT NULL DEFAULT 'unpublished', artifact_path text, artifact_sha256 text,
 PRIMARY KEY(job_id,attempt)
);
INSERT INTO m4_job_attempts(job_id,attempt,worker,attempt_token,publication_state,artifact_path,artifact_sha256)
 SELECT id,attempt,coalesce(worker,''),coalesce(attempt_token,''),CASE WHEN state='succeeded' THEN 'published' ELSE 'unpublished' END,artifact_path,artifact_sha256 FROM m4_jobs WHERE attempt>0
 ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION m4_record_attempt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.attempt>0 THEN
 INSERT INTO m4_job_attempts(job_id,attempt,worker,attempt_token)
 VALUES(NEW.id,NEW.attempt,coalesce(NEW.worker,''),coalesce(NEW.attempt_token,'')) ON CONFLICT DO NOTHING;
 UPDATE m4_job_attempts SET publication_state='fenced' WHERE job_id=NEW.id AND publication_state!='published' AND (attempt<NEW.attempt OR (attempt=NEW.attempt AND NEW.state IN ('queued','failed','cancelling','cancelled')));
 IF NEW.state='succeeded' THEN
 UPDATE m4_job_attempts SET publication_state='published',artifact_path=NEW.artifact_path,artifact_sha256=NEW.artifact_sha256
 WHERE job_id=NEW.id AND attempt=NEW.attempt;
 END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS m4_attempt_history ON m4_jobs;
CREATE TRIGGER m4_attempt_history AFTER INSERT OR UPDATE ON m4_jobs FOR EACH ROW EXECUTE FUNCTION m4_record_attempt();
