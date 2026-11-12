-- V3 is explicit CSV record location; v1/v2 states and limits remain unchanged.
ALTER TABLE v3_evaluations
 DROP CONSTRAINT IF EXISTS v3_evaluations_document_json_check;
ALTER TABLE v3_evaluations
 ADD CONSTRAINT v3_evaluations_document_json_check CHECK (COALESCE((
   ((document->'manifest.json'->>'version')='evaluation-bundle-1'
      AND octet_length(document_json)<=8388608)
   OR ((document->'manifest.json'->>'version') IN ('evaluation-bundle-2','evaluation-bundle-3')
      AND octet_length(document_json)<=134217728)
 ),false));
