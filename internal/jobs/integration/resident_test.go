package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/TonyP4N/cpagx-go/internal/jobapi"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResidentRegistrationGuardianAndInterruptedRecovery(t *testing.T) {
	dsn := os.Getenv("M4_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated postgres required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var name string
	must(db.QueryRow("SELECT current_database()").Scan(&name))
	if name != "m4_validation" {
		t.Fatal("disposable database required")
	}
	files, err := os.ReadDir("../migrations")
	must(err)
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".sql") {
			b, e := os.ReadFile("../migrations/" + f.Name())
			must(e)
			_, e = db.Exec(string(b))
			must(e)
		}
	}
	_, err = db.Exec("TRUNCATE m4_jobs CASCADE")
	must(err)
	ctx := context.Background()
	root := t.TempDir()
	repo := jobs.Repository{DB: db, ControlRoot: root}
	uid := "0c3a6291-1ec0-4550-9220-62c135c8cedc"
	location := "resident:" + uid
	identity := jobs.ResidentExecution{Version: "resident-registration-1", Namespace: "cpag", PodName: "worker-0", PodUID: uid, ContainerName: "worker", ContainerID: "containerd://" + strings.Repeat("a", 64)}
	must(repo.Enqueue(ctx, "resident-success", 2))
	handler, err := jobapi.NewWithCoordinator(repo, t.TempDir(), strings.Repeat("w", 32), strings.Repeat("c", 32), root)
	must(err)
	request := httptest.NewRequest("POST", "/v1/claim", bytes.NewBufferString(`{"worker":"worker","lease_seconds":60,"execution_type":"resident-v1","location":"`+location+`"}`))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("w", 32))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal("resident API claim", response.Code, response.Body.String())
	}
	var wire struct {
		ID            string `json:"id"`
		Attempt       int    `json:"attempt"`
		Worker        string `json:"worker"`
		Token         string `json:"token"`
		ExecutionType string `json:"execution_type"`
	}
	must(json.Unmarshal(response.Body.Bytes(), &wire))
	if wire.ExecutionType != "resident-v1" {
		t.Fatal("execution type lost")
	}
	c := jobs.Claim{ID: wire.ID, Attempt: wire.Attempt, Worker: wire.Worker, Token: wire.Token}
	if err = repo.CheckPublication(ctx, c); err == nil {
		t.Fatal("unregistered published")
	}
	must(repo.RegisterResidentExecution(ctx, c, location, identity.ContainerID, identity))
	must(repo.RegisterResidentExecution(ctx, c, location, identity.ContainerID, identity))
	changed := identity
	changed.PodName = "other"
	if err = repo.RegisterResidentExecution(ctx, c, location, identity.ContainerID, changed); !errors.Is(err, jobs.ErrStale) {
		t.Fatal("registration changed", err)
	}
	zero := 0
	k := identity
	k.Version = "resident-guardian-1"
	k.Reason = "exited"
	k.GroupExited = true
	k.ChildPID = 4
	k.GuardianPID = 3
	k.ReturnCode = &zero
	proof := jobs.ExitProof{ID: c.ID, Attempt: c.Attempt, Worker: c.Worker, Token: c.Token, Location: location, ContainerID: identity.ContainerID, Scope: "resident-process-group", Exited: true, Resident: &k}
	if err = repo.RecordExit(ctx, c, proof); err == nil {
		t.Fatal("caller body replaced trusted file")
	}
	dir := filepath.Join(root, "jobs", c.ID, "attempt-1.worker")
	must(os.MkdirAll(dir, 0700))
	raw, _ := json.Marshal(proof)
	file := filepath.Join(dir, "exit.json")
	must(os.WriteFile(file, raw, 0600))
	must(repo.RecordExit(ctx, c, proof))
	must(repo.CheckPublication(ctx, c))
	must(os.Remove(file))
	if err = repo.CheckPublication(ctx, c); err == nil {
		t.Fatal("cached proof replaced deleted file")
	}
	must(os.WriteFile(file, raw, 0600))
	k.Reason = "timeout"
	raw, _ = json.Marshal(proof)
	_, err = db.Exec("UPDATE m4_job_attempts SET exit_receipt=$2::jsonb WHERE job_id=$1", c.ID, string(raw))
	must(err)
	must(os.WriteFile(file, raw, 0600))
	if err = repo.CheckPublication(ctx, c); err == nil {
		t.Fatal("timeout published")
	}
	must(repo.Cancel(ctx, c.ID))
	must(repo.Enqueue(ctx, "resident-crash", 2))
	crash, err := repo.ClaimExecution(ctx, "worker", time.Minute, "resident-v1", location)
	must(err)
	must(repo.RegisterResidentExecution(ctx, crash, location, identity.ContainerID, identity))
	must(repo.Cancel(ctx, crash.ID))
	_, err = db.Exec("UPDATE m4_jobs SET recovery_deadline=clock_timestamp()-interval '1 second' WHERE id=$1", crash.ID)
	must(err)
	meta := map[string]any{"uid": uid, "name": "worker-0", "namespace": "cpag"}
	state := map[string]any{"running": map[string]any{}}
	pod := map[string]any{"metadata": meta, "status": map[string]any{"containerStatuses": []any{map[string]any{"name": "worker", "state": state}}}}
	repo.PodGet = func(context.Context, string, string) ([]byte, error) { return json.Marshal(pod) }
	must(repo.Recover(ctx, root))
	st, err := repo.Status(ctx, crash.ID)
	must(err)
	if st.State != "cancelling" {
		t.Fatal("running container settled", st.State)
	}
	state["terminated"] = map[string]any{"containerID": identity.ContainerID, "exitCode": 137, "finishedAt": time.Now().UTC().Format(time.RFC3339Nano)}
	delete(state, "running")
	meta["uid"] = "ea28a1ad-8246-4420-8993-ddcee4256df1"
	must(repo.Recover(ctx, root))
	st, err = repo.Status(ctx, crash.ID)
	must(err)
	if st.State != "cancelling" {
		t.Fatal("replacement Pod settled", st.State)
	}
	meta["uid"] = uid
	must(repo.Recover(ctx, root))
	st, err = repo.Status(ctx, crash.ID)
	must(err)
	if st.State != "cancelled" {
		t.Fatal("exact terminated container not recovered", st.State)
	}
	history, err := repo.History(ctx, crash.ID)
	must(err)
	if history[0].ExitedAt == nil || !strings.Contains(string(history[0].ExitEvidence), "resident-container-terminated-1") {
		t.Fatal("recovery evidence missing")
	}
}
