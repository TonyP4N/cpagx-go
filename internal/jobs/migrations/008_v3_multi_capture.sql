-- Preserve old scalar bindings; new multi-capture runs bind every ordered ID.
ALTER TABLE v3_run_bindings ADD COLUMN IF NOT EXISTS network_file_ids jsonb;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='v3_run_network_ids_shape') THEN
 ALTER TABLE v3_run_bindings ADD CONSTRAINT v3_run_network_ids_shape CHECK (
 network_file_ids IS NULL OR (jsonb_typeof(network_file_ids)='array' AND jsonb_array_length(network_file_ids) BETWEEN 2 AND 4 AND network_file_ids->>0=network_file_id));
 END IF;
END $$;
-- JSON arrays do not carry foreign keys, so enforce the same ownership and
-- role protection as scalar references for every capture at write/delete time.
CREATE OR REPLACE FUNCTION v3_validate_capture_binding() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE capture_id text; seen text[] := ARRAY[]::text[];
BEGIN
 IF NEW.network_file_ids IS NULL THEN RETURN NEW; END IF;
 FOR capture_id IN SELECT jsonb_array_elements_text(NEW.network_file_ids) LOOP
  IF capture_id=ANY(seen) OR NOT EXISTS(SELECT 1 FROM v3_dataset_files WHERE id=capture_id AND dataset_id=NEW.dataset_id AND role='network') THEN
   RAISE EXCEPTION 'invalid network capture ownership or duplicate';
  END IF;
  seen:=array_append(seen,capture_id);
 END LOOP;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS v3_capture_binding_validate ON v3_run_bindings;
CREATE TRIGGER v3_capture_binding_validate BEFORE INSERT OR UPDATE OF network_file_ids,dataset_id,network_file_id ON v3_run_bindings FOR EACH ROW EXECUTE FUNCTION v3_validate_capture_binding();
CREATE OR REPLACE FUNCTION v3_protect_capture_source() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM v3_run_bindings WHERE network_file_ids ? OLD.id) THEN
  RAISE EXCEPTION 'network capture is bound to an immutable run';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS v3_capture_source_protect ON v3_dataset_files;
CREATE TRIGGER v3_capture_source_protect BEFORE DELETE OR UPDATE OF id,dataset_id,source_file_id,role ON v3_dataset_files FOR EACH ROW EXECUTE FUNCTION v3_protect_capture_source();
