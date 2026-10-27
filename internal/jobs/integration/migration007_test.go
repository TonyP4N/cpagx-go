package integration

import (
	"context"
	"database/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"os"
	"path/filepath"
	"testing"
)

func TestMigration007CanApplyTwice(t *testing.T) {
	dsn := os.Getenv("M4_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated M4_TEST_DATABASE_URL required")
	}
	db, e := sql.Open("pgx", dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	ctx := context.Background()
	var name string
	if e = db.QueryRowContext(ctx, "SELECT current_database()").Scan(&name); e != nil {
		t.Fatal(e)
	}
	if name != "m4_validation" {
		t.Fatalf("refusing migration test on %q", name)
	}
	for _, file := range []string{"001_jobs.sql", "002_worker_api.sql", "003_recovery.sql", "004_attempt_history.sql", "005_exit_diagnostics.sql", "006_v3_catalog.sql", "007_v3_preflight_snapshots.sql", "007_v3_preflight_snapshots.sql"} {
		raw, e := os.ReadFile(filepath.Join("..", "migrations", file))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, string(raw)); e != nil {
			t.Fatalf("apply %s: %v", file, e)
		}
	}
	for _, constraint := range []string{"v3_preflight_snapshot_state", "v3_preflight_dataset_identity", "v3_run_preflight_identity", "v3_run_preflight_origin"} {
		var count int
		if e = db.QueryRowContext(ctx, "SELECT count(*) FROM pg_constraint WHERE conname=$1", constraint).Scan(&count); e != nil {
			t.Fatal(e)
		}
		if count != 1 {
			t.Fatalf("constraint %s count=%d", constraint, count)
		}
	}
}
