-- Independent recovery audit and explicit cancellation deadline.
ALTER TABLE m4_jobs ADD COLUMN IF NOT EXISTS recovery_deadline timestamptz;
ALTER TABLE m4_jobs ADD COLUMN IF NOT EXISTS recovery_checked_at timestamptz;
ALTER TABLE m4_jobs ADD COLUMN IF NOT EXISTS recovery_reason text;
-- Preexisting cancellation requests become eligible at migration time.
UPDATE m4_jobs SET recovery_deadline=clock_timestamp()
 WHERE state='cancelling' AND recovery_deadline IS NULL;
