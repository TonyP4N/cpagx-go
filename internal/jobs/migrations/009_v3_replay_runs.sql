-- R18 adds an explicit task mode; task states and historical bindings are unchanged.
ALTER TABLE v3_run_bindings ADD COLUMN IF NOT EXISTS replay_version text;
ALTER TABLE v3_run_bindings DROP CONSTRAINT IF EXISTS v3_run_bindings_mode_check;
ALTER TABLE v3_run_bindings ADD CONSTRAINT v3_run_bindings_mode_check CHECK(mode IN ('dual_source','dual_source_replay'));
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='v3_run_replay_version' AND conrelid='v3_run_bindings'::regclass) THEN
 ALTER TABLE v3_run_bindings ADD CONSTRAINT v3_run_replay_version CHECK (
 (mode='dual_source' AND replay_version IS NULL) OR
 (mode='dual_source_replay' AND replay_version IS NOT NULL AND replay_version ~ '^[a-z0-9-]{1,100}$'));
 END IF;
END $$;
