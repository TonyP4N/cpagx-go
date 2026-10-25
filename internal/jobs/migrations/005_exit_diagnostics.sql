-- Retain per-attempt recovery diagnostics; dependency outages still abort/log a pass.
ALTER TABLE m4_job_attempts ADD COLUMN IF NOT EXISTS exit_checked_at timestamptz;
ALTER TABLE m4_job_attempts ADD COLUMN IF NOT EXISTS exit_error text;
-- Only explicitly gated isolated claims may be proven never started by revocation.
ALTER TABLE m4_job_attempts ADD COLUMN IF NOT EXISTS executor_kind text NOT NULL DEFAULT 'legacy';
ALTER TABLE m4_job_attempts ADD COLUMN IF NOT EXISTS start_revoked_at timestamptz;
