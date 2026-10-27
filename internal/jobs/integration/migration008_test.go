package integration

import (
	"context"
	"database/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigration008CaptureBindings(t *testing.T) {
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
	for _, file := range []string{"001_jobs.sql", "002_worker_api.sql", "003_recovery.sql", "004_attempt_history.sql", "005_exit_diagnostics.sql", "006_v3_catalog.sql", "007_v3_preflight_snapshots.sql", "008_v3_multi_capture.sql", "008_v3_multi_capture.sql"} {
		raw, e := os.ReadFile(filepath.Join("..", "migrations", file))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, string(raw)); e != nil {
			t.Fatalf("apply %s: %v", file, e)
		}
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	seed := []string{
		`INSERT INTO v3_users(id,username,role,password_hash)VALUES('r17-constraint-user','r17-constraint-user','admin','fixture')`,
		`INSERT INTO v3_datasets(id,name,source_kind,source,batch,authorization_ref,created_by)VALUES('r17-constraint-ds','fixture','synthetic','s','b','a','r17-constraint-user')`,
		`INSERT INTO v3_config_versions(id,dataset_id,kind,version,profile_storage_path,profile_sha256,config_fingerprint,profile_json,created_by)VALUES('r17-constraint-cfg','r17-constraint-ds','dual',1,'inputs/r17-constraint-profile.json','` + strings.Repeat("a", 64) + `','` + strings.Repeat("a", 64) + `','{}','r17-constraint-user')`,
	}
	for _, q := range seed {
		if _, e = tx.ExecContext(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	for _, id := range []string{"n1", "n2", "p1"} {
		role := "network"
		if id == "p1" {
			role = "process"
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO v3_source_files(id,sha256,size_bytes,storage_path)VALUES($1,$2,1,$3)`, "r17-constraint-"+id, strings.Repeat("a", 64), "inputs/r17-constraint-"+id); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO v3_dataset_files(id,dataset_id,source_file_id,role,filename,idempotency_key,created_by)VALUES($1,'r17-constraint-ds',$1,$2,$1,$1,'r17-constraint-user')`, "r17-constraint-"+id, role); e != nil {
			t.Fatal(e)
		}
	}
	insert := func(id string, array any) error {
		if _, e = tx.ExecContext(ctx, `INSERT INTO m4_jobs(id,payload,max_attempts)VALUES($1,'{}',3)`, id); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO v3_run_bindings(job_id,dataset_id,network_file_id,process_file_id,config_version_id,mode,created_by,network_file_ids)VALUES($1,'r17-constraint-ds','r17-constraint-n1','r17-constraint-p1','r17-constraint-cfg','dual_source','r17-constraint-user',$2)`, id, array)
		return e
	}
	if e = insert("r17-constraint-legacy", nil); e != nil {
		t.Fatalf("legacy scalar: %v", e)
	}
	if e = insert("r17-constraint-multi", `["r17-constraint-n1","r17-constraint-n2"]`); e != nil {
		t.Fatalf("valid ordered captures: %v", e)
	}
	reject := func(name string, action func() error) {
		if _, e = tx.ExecContext(ctx, "SAVEPOINT rejected"); e != nil {
			t.Fatal(e)
		}
		if e = action(); e == nil {
			t.Fatalf("%s accepted", name)
		}
		if _, e = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT rejected"); e != nil {
			t.Fatal(e)
		}
	}
	for name, array := range map[string]string{"duplicate": `["r17-constraint-n1","r17-constraint-n1"]`, "wrong_role": `["r17-constraint-n1","r17-constraint-p1"]`, "missing": `["r17-constraint-n1","not-present"]`, "primary": `["r17-constraint-n2","r17-constraint-n1"]`, "five": `["r17-constraint-n1","a","b","c","d"]`} {
		reject(name, func() error { return insert("r17-constraint-"+name, array) })
	}
	reject("bound secondary delete", func() error {
		_, e := tx.ExecContext(ctx, `DELETE FROM v3_dataset_files WHERE id='r17-constraint-n2'`)
		return e
	})
	reject("bound secondary mutation", func() error {
		_, e := tx.ExecContext(ctx, `UPDATE v3_dataset_files SET role='process' WHERE id='r17-constraint-n2'`)
		return e
	})
}
