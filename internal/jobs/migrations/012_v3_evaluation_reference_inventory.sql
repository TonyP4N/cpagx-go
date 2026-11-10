-- Explicit evaluation v2 carries a bounded, hash-verified reference inventory.
-- Historical v1 documents retain their original 8 MiB limit and semantics.
ALTER TABLE v3_evaluations
 DROP CONSTRAINT IF EXISTS v3_evaluations_document_json_check;
ALTER TABLE v3_evaluations
 ADD CONSTRAINT v3_evaluations_document_json_check CHECK (COALESCE((
   ((document->'manifest.json'->>'version')='evaluation-bundle-1'
      AND octet_length(document_json)<=8388608)
   OR ((document->'manifest.json'->>'version')='evaluation-bundle-2'
      AND octet_length(document_json)<=134217728)
 ),false));
