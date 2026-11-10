-- Default stays polling. Rabbit dispatch is an explicit per-job partition.
ALTER TABLE m4_jobs ADD COLUMN IF NOT EXISTS dispatch_partition text NOT NULL DEFAULT 'poll' CHECK(dispatch_partition IN ('poll','rabbit-v3'));
ALTER TABLE m4_jobs ADD COLUMN IF NOT EXISTS dispatch_id text;
ALTER TABLE m4_job_attempts ADD COLUMN IF NOT EXISTS dispatch_id text;
CREATE TABLE IF NOT EXISTS m4_dispatch_outbox (
 dispatch_id text PRIMARY KEY CHECK(dispatch_id ~ '^[0-9a-f]{32}$'),
 job_id text NOT NULL REFERENCES m4_jobs(id) ON DELETE CASCADE,
 partition text NOT NULL CHECK(partition='rabbit-v3'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 publisher text,lease_token text,leased_until timestamptz,
 confirmed_at timestamptz,invalidated_at timestamptz,
 publish_attempts integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS m4_dispatch_pending ON m4_dispatch_outbox(created_at) WHERE confirmed_at IS NULL AND invalidated_at IS NULL;
CREATE INDEX IF NOT EXISTS m4_dispatch_live_job ON m4_dispatch_outbox(job_id) WHERE invalidated_at IS NULL;
CREATE OR REPLACE FUNCTION m4_prepare_dispatch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.dispatch_partition='rabbit-v3' AND NEW.state='queued' THEN
  IF TG_OP='INSERT' THEN
   NEW.dispatch_id=replace(gen_random_uuid()::text,'-','');
  ELSIF OLD.state!='queued' OR OLD.dispatch_partition!='rabbit-v3' THEN
   NEW.dispatch_id=replace(gen_random_uuid()::text,'-','');
  ELSE
   NEW.dispatch_id=OLD.dispatch_id;
  END IF;
 ELSIF NEW.dispatch_partition='poll' THEN
  NEW.dispatch_id=NULL;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS m4_prepare_dispatch ON m4_jobs;
CREATE TRIGGER m4_prepare_dispatch BEFORE INSERT OR UPDATE ON m4_jobs FOR EACH ROW EXECUTE FUNCTION m4_prepare_dispatch();
CREATE OR REPLACE FUNCTION m4_record_dispatch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.dispatch_partition='poll' THEN RETURN NEW; END IF;
 ELSIF NEW.state=OLD.state AND NEW.dispatch_partition=OLD.dispatch_partition AND NEW.dispatch_id IS NOT DISTINCT FROM OLD.dispatch_id THEN
  RETURN NEW;
 END IF;
 UPDATE m4_dispatch_outbox SET invalidated_at=coalesce(invalidated_at,clock_timestamp())
 WHERE job_id=NEW.id AND invalidated_at IS NULL AND (NEW.state!='queued' OR NEW.dispatch_partition!='rabbit-v3' OR dispatch_id IS DISTINCT FROM NEW.dispatch_id);
 IF NEW.dispatch_partition='rabbit-v3' AND NEW.state='queued' THEN
  INSERT INTO m4_dispatch_outbox(dispatch_id,job_id,partition) VALUES(NEW.dispatch_id,NEW.id,'rabbit-v3') ON CONFLICT DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS m4_record_dispatch ON m4_jobs;
CREATE TRIGGER m4_record_dispatch AFTER INSERT OR UPDATE ON m4_jobs FOR EACH ROW EXECUTE FUNCTION m4_record_dispatch();
