-- Bind resident attempts to the exact Pod/container before launching compute.
ALTER TABLE m4_job_attempts ADD COLUMN IF NOT EXISTS resident_execution jsonb;
