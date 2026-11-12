-- Explicit DAG6 execution format, with the same one-unexited-attempt gate.
ALTER TABLE m4_capacity_policy DROP CONSTRAINT IF EXISTS m4_capacity_policy_profile_check;
ALTER TABLE m4_capacity_policy ADD CONSTRAINT m4_capacity_policy_profile_check CHECK(profile IN ('','engineering-capacity-1','engineering-capacity-2','engineering-core-capacity-3'));
CREATE OR REPLACE FUNCTION m4_capacity_claim_gate() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE chosen text;
BEGIN
 IF NEW.attempt > 0 AND (TG_OP='INSERT' OR NEW.attempt>OLD.attempt) THEN
  PERFORM pg_advisory_xact_lock(19002801);
  SELECT profile INTO chosen FROM m4_capacity_policy WHERE singleton=true;
  IF chosen IS NULL THEN RAISE EXCEPTION 'site capacity: policy row missing' USING ERRCODE='55000'; END IF;
  IF chosen IN ('engineering-capacity-1','engineering-capacity-2','engineering-core-capacity-3') THEN
   IF EXISTS(SELECT 1 FROM m4_job_attempts WHERE exited_at IS NULL) OR
      EXISTS(SELECT 1 FROM m4_jobs j WHERE j.attempt>0 AND NOT EXISTS(
       SELECT 1 FROM m4_job_attempts a WHERE a.job_id=j.id AND a.attempt=j.attempt AND a.exited_at IS NOT NULL)) OR EXISTS(SELECT 1 FROM m4_compact_verifications WHERE state='running') THEN
    RAISE EXCEPTION 'site capacity: previous attempt has no verified exit' USING ERRCODE='55000';
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TABLE IF NOT EXISTS m4_compact_verifications (
 job_id text NOT NULL REFERENCES m4_jobs(id), attempt integer NOT NULL,
 container_name text NOT NULL, state text NOT NULL CHECK(state IN ('running','exited')),
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(), exited_at timestamptz,
 PRIMARY KEY(job_id,attempt), CHECK((state='exited')=(exited_at IS NOT NULL))
);
