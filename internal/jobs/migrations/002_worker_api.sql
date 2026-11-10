-- Additive opt-in HTTP worker support. Apply after 001_jobs.sql.
ALTER TABLE m4_jobs ADD COLUMN IF NOT EXISTS payload jsonb NOT NULL DEFAULT '{}';
ALTER TABLE m4_jobs ADD COLUMN IF NOT EXISTS attempt_token text;
