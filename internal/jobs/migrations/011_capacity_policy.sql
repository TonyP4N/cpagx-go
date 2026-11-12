-- Disabled by default. Once explicitly enabled, absent operator configuration
-- does not disable a persisted site policy. Dump/restore retains this row.
CREATE TABLE IF NOT EXISTS m4_capacity_policy (
 singleton boolean PRIMARY KEY CHECK (singleton),
 profile text NOT NULL CHECK (profile IN ('','engineering-capacity-1')),
 enabled_at timestamptz
);
INSERT INTO m4_capacity_policy(singleton,profile) VALUES(true,'') ON CONFLICT DO NOTHING;

-- Defense in depth for mixed application versions sharing this database. A
-- stale lease, failed job or cancelling state is not proof computation exited.
CREATE OR REPLACE FUNCTION m4_capacity_claim_gate() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE chosen text;
BEGIN
 IF NEW.attempt > 0 AND (TG_OP='INSERT' OR NEW.attempt>OLD.attempt) THEN
  PERFORM pg_advisory_xact_lock(19002801);
  SELECT profile INTO chosen FROM m4_capacity_policy WHERE singleton=true;
  IF chosen IS NULL THEN
   RAISE EXCEPTION 'site capacity: policy row missing' USING ERRCODE='55000';
  END IF;
  -- Keep the disabled branch independent of the post-004 attempt table. SQL
  -- plans every relation in a compound AND before evaluating its boolean left
  -- side, so a disabled policy must use a distinct PL/pgSQL control-flow block
  -- while historical migrations reconstruct that table transactionally.
  IF chosen='engineering-capacity-1' THEN
   IF EXISTS(SELECT 1 FROM m4_job_attempts WHERE exited_at IS NULL) OR
      EXISTS(SELECT 1 FROM m4_jobs j WHERE j.attempt>0 AND NOT EXISTS(
       SELECT 1 FROM m4_job_attempts a WHERE a.job_id=j.id AND a.attempt=j.attempt AND a.exited_at IS NOT NULL)) THEN
    RAISE EXCEPTION 'site capacity: previous attempt has no verified exit' USING ERRCODE='55000';
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS m4_capacity_claim ON m4_jobs;
CREATE TRIGGER m4_capacity_claim BEFORE INSERT OR UPDATE ON m4_jobs FOR EACH ROW EXECUTE FUNCTION m4_capacity_claim_gate();
