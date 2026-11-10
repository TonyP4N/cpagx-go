-- Additive v3 catalog. Apply after 001..005; the legacy/default API is unchanged.
CREATE TABLE IF NOT EXISTS v3_users (
 id text PRIMARY KEY, username text NOT NULL UNIQUE,
 role text NOT NULL CHECK(role IN ('admin','analyst','viewer')),
 password_hash text NOT NULL, disabled_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS v3_sessions (
 id text PRIMARY KEY, user_id text NOT NULL REFERENCES v3_users(id),
 token_hash text NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL, revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS v3_sessions_active ON v3_sessions(token_hash,expires_at) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS v3_datasets (
 id text PRIMARY KEY, name text NOT NULL,
 source_kind text NOT NULL CHECK(source_kind IN ('synthetic','real')),
 verification_status text NOT NULL DEFAULT 'accepted_unvalidated'
   CHECK(verification_status IN ('accepted_unvalidated','metadata_checked','rejected')),
 source text NOT NULL, batch text NOT NULL, authorization_ref text NOT NULL,
 created_by text NOT NULL REFERENCES v3_users(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS v3_dataset_acl (
 dataset_id text NOT NULL REFERENCES v3_datasets(id),
 user_id text NOT NULL REFERENCES v3_users(id),
 access text NOT NULL CHECK(access IN ('viewer','analyst','owner')),
 PRIMARY KEY(dataset_id,user_id)
);
CREATE TABLE IF NOT EXISTS v3_source_files (
 id text PRIMARY KEY, sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 size_bytes bigint NOT NULL CHECK(size_bytes >= 0), storage_path text NOT NULL UNIQUE,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS v3_dataset_files (
 id text PRIMARY KEY, dataset_id text NOT NULL REFERENCES v3_datasets(id),
 source_file_id text NOT NULL REFERENCES v3_source_files(id),
 role text NOT NULL CHECK(role IN ('network','process')),
 filename text NOT NULL, idempotency_key text NOT NULL,
 created_by text NOT NULL REFERENCES v3_users(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(dataset_id,idempotency_key), UNIQUE(dataset_id,id)
);
CREATE INDEX IF NOT EXISTS v3_dataset_files_by_dataset ON v3_dataset_files(dataset_id,role);
CREATE TABLE IF NOT EXISTS v3_config_versions (
 id text PRIMARY KEY, dataset_id text NOT NULL REFERENCES v3_datasets(id),
 kind text NOT NULL CHECK(kind IN ('intake','dual')),
 version integer NOT NULL CHECK(version>0),
 profile_storage_path text NOT NULL UNIQUE,
 profile_sha256 text NOT NULL CHECK(profile_sha256 ~ '^[0-9a-f]{64}$'),
 config_fingerprint text NOT NULL CHECK(config_fingerprint ~ '^[0-9a-f]{64}$'),
 profile_json jsonb NOT NULL, created_by text NOT NULL REFERENCES v3_users(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(dataset_id,kind,version), UNIQUE(dataset_id,id)
);
CREATE TABLE IF NOT EXISTS v3_run_bindings (
 job_id text PRIMARY KEY REFERENCES m4_jobs(id),
 dataset_id text NOT NULL REFERENCES v3_datasets(id),
 network_file_id text NOT NULL, process_file_id text NOT NULL,
 config_version_id text NOT NULL, mode text NOT NULL CHECK(mode='dual_source'),
 created_by text NOT NULL REFERENCES v3_users(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(dataset_id,network_file_id) REFERENCES v3_dataset_files(dataset_id,id),
 FOREIGN KEY(dataset_id,process_file_id) REFERENCES v3_dataset_files(dataset_id,id),
 FOREIGN KEY(dataset_id,config_version_id) REFERENCES v3_config_versions(dataset_id,id)
);
CREATE INDEX IF NOT EXISTS v3_runs_by_dataset ON v3_run_bindings(dataset_id,created_at);
CREATE TABLE IF NOT EXISTS v3_preflights (
 id text PRIMARY KEY, dataset_id text NOT NULL REFERENCES v3_datasets(id),
 config_version_id text NOT NULL REFERENCES v3_config_versions(id),
 report jsonb NOT NULL, created_by text NOT NULL REFERENCES v3_users(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS v3_audit_events (
 id bigserial PRIMARY KEY, occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 user_id text REFERENCES v3_users(id), dataset_id text REFERENCES v3_datasets(id),
 job_id text REFERENCES m4_jobs(id), action text NOT NULL, outcome text NOT NULL,
 details jsonb NOT NULL DEFAULT '{}'
);
