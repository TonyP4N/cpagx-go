//go:build linux || darwin

package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/jobs"
)

func TestComposeRegistrationTrustedGenerationRecoveryAndGuardian(t *testing.T) {
	dsn := os.Getenv("M4_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated postgres required")
	}
	db, e := sql.Open("pgx", dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var database string
	must(db.QueryRow("SELECT current_database()").Scan(&database))
	if database != "m4_validation" {
		t.Fatal("isolated database required")
	}
	migrations, e := os.ReadDir("../migrations")
	must(e)
	for _, f := range migrations {
		if strings.HasSuffix(f.Name(), ".sql") {
			raw, err := os.ReadFile("../migrations/" + f.Name())
			must(err)
			_, err = db.Exec(string(raw))
			must(err)
		}
	}
	_, e = db.Exec("TRUNCATE m4_jobs CASCADE; UPDATE m4_capacity_policy SET profile=''")
	must(e)
	ctx := context.Background()
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	must(os.Chmod(root, 0700))
	repo := jobs.Repository{DB: db, ControlRoot: root, PodGet: func(context.Context, string, string) ([]byte, error) {
		t.Fatal("Compose accessed Kubernetes")
		return nil, nil
	}}
	location := "resident-compose:" + strings.Repeat("a", 32)
	p := jobs.ResidentExecution{Version: "resident-registration-1", Backend: "compose-pid1-v1", DeploymentID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), SupervisorID: "worker-01", ContainerID: "pid1://" + strings.Repeat("b", 32)}
	lock := func(p jobs.ResidentExecution) *os.File {
		t.Helper()
		dir := filepath.Join(root, "resident-generations")
		must(os.MkdirAll(dir, 0700))
		raw, err := json.Marshal(map[string]any{"version": "resident-compose-generation-1", "deployment_id": p.DeploymentID, "generation": p.Generation, "supervisor_id": p.SupervisorID, "pid": 1})
		must(err)
		f, err := os.OpenFile(filepath.Join(dir, p.Generation+".lock"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		must(err)
		t.Cleanup(func() { f.Close() })
		_, err = f.Write(raw)
		must(err)
		must(f.Sync())
		must(syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))
		must(os.WriteFile(filepath.Join(root, "resident-current.json"), raw, 0600))
		return f
	}
	old := lock(p)
	must(repo.Enqueue(ctx, "compose-interrupted", 2))
	c, e := repo.ClaimExecution(ctx, "worker-01", time.Minute, "resident-v1", location)
	must(e)
	must(repo.RegisterResidentExecution(ctx, c, location, p.ContainerID, p))
	must(repo.Cancel(ctx, c.ID))
	_, e = db.Exec("UPDATE m4_jobs SET recovery_deadline=clock_timestamp()-interval '1 second' WHERE id=$1", c.ID)
	must(e)
	assertPending := func() {
		t.Helper()
		must(repo.Recover(ctx, root))
		history, err := repo.History(ctx, c.ID)
		must(err)
		if history[0].ExitedAt != nil {
			t.Fatal("insufficient PID1 termination proof accepted")
		}
	}
	assertPending()
	replacement := p
	replacement.Generation = strings.Repeat("c", 32)
	replacement.ContainerID = "pid1://" + replacement.Generation
	current := lock(replacement)
	assertPending()
	must(old.Close())
	must(current.Close())
	assertPending()
	// Missing, unlocked or unrelated replacement cannot settle termination.
	replacement.Generation = strings.Repeat("d", 32)
	replacement.ContainerID = "pid1://" + replacement.Generation
	lock(replacement)
	must(repo.Recover(ctx, root))
	st, e := repo.Status(ctx, c.ID)
	must(e)
	if st.State != "cancelled" {
		t.Fatal("replacement active + old unlocked did not settle", st.State)
	}
	var evidence struct {
		Resident jobs.ResidentExecution `json:"resident"`
	}
	must(json.Unmarshal(st.AttemptHistory[0].ExitEvidence, &evidence))
	if evidence.Resident.Version != "resident-compose-terminated-1" || evidence.Resident.ReturnCode != nil || evidence.Resident.ObservedAt == nil {
		t.Fatal("recovery mislabeled clean exit", evidence)
	}
	// A normal private guardian proof still permits publication in this backend.
	must(repo.Enqueue(ctx, "compose-clean", 2))
	clean, e := repo.ClaimExecution(ctx, "worker-01", time.Minute, "resident-v1", location)
	must(e)
	must(repo.RegisterResidentExecution(ctx, clean, location, replacement.ContainerID, replacement))
	zero := 0
	guardian := replacement
	guardian.Version = "resident-guardian-1"
	guardian.Reason = "exited"
	guardian.GroupExited = true
	guardian.ChildPID = 3
	guardian.GuardianPID = 2
	guardian.ReturnCode = &zero
	proof := jobs.ExitProof{ID: clean.ID, Attempt: clean.Attempt, Worker: clean.Worker, Token: clean.Token, Scope: "resident-process-group", Location: location, ContainerID: replacement.ContainerID, Exited: true, Resident: &guardian}
	dir := filepath.Join(root, "jobs", clean.ID, "attempt-1.worker")
	must(os.MkdirAll(dir, 0700))
	raw, _ := json.Marshal(proof)
	must(os.WriteFile(filepath.Join(dir, "exit.json"), raw, 0600))
	must(repo.RecordExit(ctx, clean, proof))
	must(repo.CheckPublication(ctx, clean))
}
