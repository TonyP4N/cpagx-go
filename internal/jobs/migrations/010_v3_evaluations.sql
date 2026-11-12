-- R19 stores opt-in independently evaluated sidecars, never analysis artifacts.
CREATE TABLE IF NOT EXISTS v3_evaluations (
 id text PRIMARY KEY,
 job_id text NOT NULL REFERENCES m4_jobs(id),
 dataset_id text NOT NULL REFERENCES v3_datasets(id),
 document jsonb NOT NULL CHECK(jsonb_typeof(document)='object'),
 -- JSONB normalizes exponent spellings. Retain the verified serialization so
 -- Python's frozen int/float fingerprints survive PostgreSQL round trips.
 document_json text NOT NULL CHECK(octet_length(document_json)<=8388608),
 document_sha256 text NOT NULL CHECK(document_sha256 ~ '^[a-f0-9]{64}$'),
 created_by text NOT NULL REFERENCES v3_users(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(document_json::jsonb=document),
 UNIQUE(job_id,document_sha256)
);
CREATE INDEX IF NOT EXISTS v3_evaluations_by_run ON v3_evaluations(job_id,created_at,id);
