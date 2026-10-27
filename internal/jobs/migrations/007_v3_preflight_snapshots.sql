-- Additive R16 supplement. Existing reports and runs are retained unchanged.
-- Run the explicit --backfill-legacy command during maintenance after applying.
ALTER TABLE v3_preflights ADD COLUMN IF NOT EXISTS snapshot_json text;
ALTER TABLE v3_preflights ADD COLUMN IF NOT EXISTS snapshot_sha256 text;
ALTER TABLE v3_preflights ADD COLUMN IF NOT EXISTS snapshot_status text NOT NULL DEFAULT 'pending_legacy';
ALTER TABLE v3_preflights ADD COLUMN IF NOT EXISTS snapshot_reason text;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='v3_preflight_snapshot_state' AND conrelid='v3_preflights'::regclass) THEN
  ALTER TABLE v3_preflights ADD CONSTRAINT v3_preflight_snapshot_state CHECK (
   (snapshot_status='pending_legacy' AND snapshot_json IS NULL AND snapshot_sha256 IS NULL AND snapshot_reason IS NULL) OR
   (snapshot_status IN ('native','reconstructed') AND snapshot_json IS NOT NULL AND snapshot_sha256 ~ '^[0-9a-f]{64}$' AND snapshot_reason IS NULL) OR
   (snapshot_status='unreconstructable' AND snapshot_json IS NULL AND snapshot_sha256 IS NULL AND length(snapshot_reason)>0)
  );
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='v3_preflight_dataset_identity' AND conrelid='v3_preflights'::regclass) THEN
  ALTER TABLE v3_preflights ADD CONSTRAINT v3_preflight_dataset_identity UNIQUE(dataset_id,id);
 END IF;
END $$;

ALTER TABLE v3_run_bindings ADD COLUMN IF NOT EXISTS preflight_id text;
ALTER TABLE v3_run_bindings ADD COLUMN IF NOT EXISTS preflight_link_origin text NOT NULL DEFAULT 'legacy_unbound';
ALTER TABLE v3_run_bindings ADD COLUMN IF NOT EXISTS preflight_link_reason text DEFAULT 'legacy run predates preflight gate';
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='v3_run_preflight_identity' AND conrelid='v3_run_bindings'::regclass) THEN
  ALTER TABLE v3_run_bindings ADD CONSTRAINT v3_run_preflight_identity FOREIGN KEY(dataset_id,preflight_id) REFERENCES v3_preflights(dataset_id,id);
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='v3_run_preflight_origin' AND conrelid='v3_run_bindings'::regclass) THEN
  ALTER TABLE v3_run_bindings ADD CONSTRAINT v3_run_preflight_origin CHECK (
   (preflight_link_origin='legacy_unbound' AND preflight_id IS NULL AND length(preflight_link_reason)>0) OR
   (preflight_link_origin IN ('native_gate','reconstructed_match') AND preflight_id IS NOT NULL AND preflight_link_reason IS NULL)
  );
 END IF;
END $$;
