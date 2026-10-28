-- Explicit, derived evaluation preparation. No analysis or annotation is changed.
-- Requested projection only: at most three independently bound views per source.
CREATE TABLE IF NOT EXISTS v3_evaluation_preparations (
 id text PRIMARY KEY,
 job_id text NOT NULL REFERENCES m4_jobs(id) ON DELETE CASCADE,
 dataset_id text NOT NULL REFERENCES v3_datasets(id) ON DELETE CASCADE,
 attempt integer NOT NULL CHECK(attempt>0),
 payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[a-f0-9]{64}$'),
 publication_sha256 text NOT NULL CHECK(publication_sha256 ~ '^[a-f0-9]{64}$'),
 artifact_path text NOT NULL,
 config_fingerprint text NOT NULL CHECK(config_fingerprint ~ '^[a-f0-9]{64}$'),
 input_fingerprint text CHECK(input_fingerprint ~ '^[a-f0-9]{64}$'),
 batch text NOT NULL CHECK(length(btrim(batch))>0),
 projection text NOT NULL CHECK(projection IN ('network','process','dual')),
 strategy_version text NOT NULL CHECK(strategy_version='evaluation-preparation-1'),
 state text NOT NULL CHECK(state IN ('queued','preparing','ready','failed')),
 preparation_attempt integer NOT NULL DEFAULT 0 CHECK(preparation_attempt BETWEEN 0 AND 100),
 coordination_scope text NOT NULL DEFAULT '',
 owner text NOT NULL DEFAULT '',
 reason_code text NOT NULL DEFAULT '',
 error_detail text NOT NULL DEFAULT '' CHECK(octet_length(error_detail)<=8192),
 document_limit bigint NOT NULL CHECK(document_limit IN (8388608,134217728)),
 document_bytes bytea,
 document_sha256 text CHECK(document_sha256 ~ '^[a-f0-9]{64}$'),
 document_size bigint NOT NULL DEFAULT 0 CHECK(document_size BETWEEN 0 AND 134217728),
 inventory_json jsonb,
 cost_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(octet_length(cost_json::text)<=16384),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 started_at timestamptz,
 finished_at timestamptz,
 UNIQUE(job_id,attempt,payload_sha256,publication_sha256,batch,projection,strategy_version),
 CHECK((state='ready')=(document_bytes IS NOT NULL AND document_sha256 IS NOT NULL AND inventory_json IS NOT NULL AND input_fingerprint IS NOT NULL)),
 CHECK(document_bytes IS NULL OR octet_length(document_bytes)=document_size),
 CHECK(document_size<=document_limit),
 CHECK(state='ready' OR (document_bytes IS NULL AND document_sha256 IS NULL AND document_size=0))
);
CREATE INDEX IF NOT EXISTS v3_evaluation_preparations_pending ON v3_evaluation_preparations(created_at,id) WHERE state IN ('queued','preparing');

-- Append one bounded diagnostic/cost entry per real preparation attempt. A
-- retried failure never erases the earlier failure or exposes a partial JSON.
CREATE TABLE IF NOT EXISTS v3_evaluation_preparation_attempts (
 preparation_id text NOT NULL REFERENCES v3_evaluation_preparations(id) ON DELETE CASCADE,
 attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 100),
 state text NOT NULL CHECK(state IN ('preparing','ready','failed')),
 owner text NOT NULL,
 reason_code text NOT NULL DEFAULT '',
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 finished_at timestamptz,
 document_sha256 text CHECK(document_sha256 ~ '^[a-f0-9]{64}$'),
 cost_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(octet_length(cost_json::text)<=16384),
 PRIMARY KEY(preparation_id,attempt)
);
