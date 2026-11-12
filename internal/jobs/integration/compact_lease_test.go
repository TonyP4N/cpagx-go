package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/capacity"
	"github.com/TonyP4N/cpagx-go/internal/jobapi"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
)

// Exercise the real HTTP/PG lease and publication path with a deliberately
// non-completing private verifier. The fake never issues a source approval.
func TestCompactPendingHTTPDoesNotStarveShortLeaseAndStopsOnOwnershipLoss(t *testing.T) {
	dsn := os.Getenv("M4_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated M4_TEST_DATABASE_URL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var name string
	must(db.QueryRow("SELECT current_database()").Scan(&name))
	if name != "m4_validation" {
		t.Fatal("dedicated disposable database required")
	}
	files, err := os.ReadDir("../migrations")
	must(err)
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".sql") {
			raw, e := os.ReadFile(filepath.Join("../migrations", file.Name()))
			must(e)
			_, e = db.Exec(string(raw))
			must(e)
		}
	}
	for _, loss := range []string{"cancel", "expire", "reject", "cleanup_error", "receipt_error"} {
		t.Run(loss, func(t *testing.T) {
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err = db.Exec("TRUNCATE m4_jobs CASCADE; UPDATE m4_capacity_policy SET profile='',enabled_at=NULL")
			must(err)
			defer db.Exec("TRUNCATE m4_jobs CASCADE; UPDATE m4_capacity_policy SET profile='',enabled_at=NULL")
			repo := jobs.Repository{DB: db}
			must(repo.EnableCapacityPolicy(ctx, capacity.EngineeringCore))
			root, err := filepath.EvalSymlinks(t.TempDir())
			must(err)
			control, err := filepath.EvalSymlinks(t.TempDir())
			must(err)
			token := strings.Repeat("w", 32)
			image := "sha256:" + strings.Repeat("b", 64)
			job := "compact-http-lease"
			bin := t.TempDir()
			script := `#!/usr/bin/env python3
import json,os,sys,time
from pathlib import Path
identity='a'*64
operation=sys.argv[1]
marker=Path(os.environ['CPAG_TEST_VERIFIER_MARKER'])
if operation=='create':print(identity)
elif operation=='inspect':
    failed=marker.with_suffix('.failed').exists()
    print(json.dumps([{'Id':identity,'Config':{'Image':'sha256:'+'b'*64,'Labels':{'cpag.role':'dag6-source-verifier','cpag.job':'compact-http-lease','cpag.attempt':'1'}},'State':{'Running':not failed,'OOMKilled':False,'ExitCode':2 if failed else 0,'Status':'exited' if failed else 'running'}}]))
elif operation=='start':
    sys.stdin.buffer.read()
    marker.write_text('started')
    if os.environ.get('CPAG_TEST_VERIFIER_MODE') in ('reject','cleanup_error','receipt_error'):
        marker.with_suffix('.failed').write_text('failed')
        print(json.dumps({'status':'failed','error_type':'ValueError','reason':'shared_business_root_does_not_match_sources:analysis.json'}),file=sys.stderr)
        raise SystemExit(2)
    while True:time.sleep(.1)
elif operation=='rm':
    if os.environ.get('CPAG_TEST_VERIFIER_MODE')=='cleanup_error':print('daemon unavailable',file=sys.stderr);raise SystemExit(125)
    marker.with_suffix('.removed').write_text('removed');print(identity)
else:raise SystemExit(2)
`
			must(os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700))
			marker := filepath.Join(control, "verifier-started")
			t.Setenv("CPAG_TEST_VERIFIER_MARKER", marker)
			t.Setenv("CPAG_TEST_VERIFIER_MODE", loss)
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			handler, err := jobapi.NewWithCoordinator(repo, root, token, strings.Repeat("c", 32), control)
			must(err)
			internal := handler.(*jobapi.Server)
			internal.CapacityPolicy = capacity.EngineeringCore
			internal.ResourceProfile = capacity.StorageBudget
			internal.CompactVerifierImage = image
			if loss == "receipt_error" {
				internal.ControlRoot = filepath.Join(control, "unavailable-receipt-root")
			}
			raw, err := os.ReadFile("../../jobapi/testdata/r19-fixed-s100-replay-profile.json")
			must(err)
			put := func(relative string, data []byte) jobapi.Ref {
				t.Helper()
				path := filepath.Join(root, relative)
				must(os.MkdirAll(filepath.Dir(path), 0700))
				must(os.WriteFile(path, data, 0400))
				return jobapi.Ref{Path: relative, SHA: sum(data)}
			}
			network := []byte("unverified raw source placeholder")
			process := []byte("time,pump\n2026-01-01T00:00:00Z,0\n")
			payload := jobapi.Payload{Kind: "dual-source-replay", Network: put("inputs/network.pcap", network), Process: put("inputs/process.csv", process), Profile: put("inputs/profile.json", raw), CapacityProfile: capacity.EngineeringCore, StorageFormat: capacity.CoreSharedFormat, StorageBudgetVersion: jobapi.SharedStorageBudget, ResourceProfile: capacity.StorageBudget, HistoryFormat: capacity.CoreSharedFormat, ReplayVersion: jobapi.ReplayVersion}
			payload.Fingerprint, err = jobapi.DualProfileFingerprint(raw)
			must(err)
			must(internal.ValidatePayload(payload))
			payloadRaw, _ := json.Marshal(payload)
			must(repo.EnqueuePayload(ctx, job, 2, payloadRaw))
			claim, err := repo.Claim(ctx, "worker", 2*time.Second)
			must(err)
			_, err = db.Exec("UPDATE m4_job_attempts SET exited_at=clock_timestamp() WHERE job_id=$1 AND attempt=1", job)
			must(err)
			base := "jobs/" + job + "/attempt-1/"
			contents := map[string][]byte{"shared/manifest.json": []byte(`{}`), "shared/shared.sqlite3": []byte("unverified sqlite placeholder"), "sources/network.pcap": network, "sources/process.csv": process, "sources/profile.json": raw}
			coreArtifacts := []map[string]any{}
			for path, data := range contents {
				put(base+path, data)
				coreArtifacts = append(coreArtifacts, map[string]any{"path": path, "sha256": sum(data), "size_bytes": len(data)})
			}
			core, _ := json.Marshal(map[string]any{"run_id": job, "attempt_id": 1, "config_fingerprint": payload.Fingerprint, "mode": "replay", "storage_format": payload.StorageFormat, "artifacts": coreArtifacts})
			contents["run_manifest.json"] = core
			put(base+"run_manifest.json", core)
			artifacts := []map[string]any{}
			for path, data := range contents {
				artifacts = append(artifacts, map[string]any{"path": path, "sha256": sum(data), "size": len(data)})
			}
			wrapper, _ := json.Marshal(map[string]any{"run_id": job, "attempt_id": 1, "capacity_profile": payload.CapacityProfile, "resource_profile": payload.ResourceProfile, "config_fingerprint": payload.Fingerprint, "storage_format": payload.StorageFormat, "storage_budget_version": payload.StorageBudgetVersion, "replay_version": payload.ReplayVersion, "history_format": payload.HistoryFormat, "inputs": map[string]string{"network": payload.Network.SHA, "process": payload.Process.SHA, "profile": payload.Profile.SHA}, "artifacts": artifacts})
			publication := put(base+"manifest.json", wrapper)
			server := httptest.NewServer(handler)
			defer server.Close()
			client := &http.Client{Timeout: time.Second}
			post := func(op string, extra map[string]any) int {
				t.Helper()
				body := map[string]any{"attempt": claim.Attempt, "worker": claim.Worker, "token": claim.Token}
				for k, v := range extra {
					body[k] = v
				}
				raw, _ := json.Marshal(body)
				req, e := http.NewRequest("POST", server.URL+"/v1/jobs/"+job+"/"+op, bytes.NewReader(raw))
				must(e)
				req.Header.Set("Authorization", "Bearer "+token)
				response, e := client.Do(req)
				must(e)
				defer response.Body.Close()
				io.Copy(io.Discard, response.Body)
				return response.StatusCode
			}
			started := time.Now()
			if code := post("complete", map[string]any{"manifest_sha256": publication.SHA}); code != 202 {
				t.Fatalf("pending complete=%d", code)
			}
			if time.Since(started) > time.Second {
				t.Fatal("complete waited for source verifier")
			}
			if loss == "reject" || loss == "cleanup_error" || loss == "receipt_error" {
				deadline := time.Now().Add(5 * time.Second)
				lastCode := 202
				for time.Now().Before(deadline) {
					lastCode = post("complete", map[string]any{"manifest_sha256": publication.SHA})
					if lastCode != 202 {
						break
					}
					if code := post("heartbeat", map[string]any{"lease_seconds": 2}); code != 200 {
						t.Fatalf("pending heartbeat=%d", code)
					}
					time.Sleep(50 * time.Millisecond)
				}
				current, e := repo.Status(ctx, job)
				must(e)
				if loss == "reject" {
					if lastCode != 409 || current.State != "failed" || current.Attempt != 1 || current.LastError == nil || !strings.Contains(*current.LastError, "shared_business_root_does_not_match_sources") {
						t.Fatalf("definitive rejection not closed: status=%d job=%+v", lastCode, current)
					}
					if _, e = repo.Claim(ctx, "next", time.Minute); !errors.Is(e, sql.ErrNoRows) {
						t.Fatalf("definitive failure retried: %v", e)
					}
					if code := post("heartbeat", map[string]any{"lease_seconds": 2}); code != 409 {
						t.Fatalf("failed task lease renewed: %d", code)
					}
				} else {
					if lastCode != 400 || current.State != "running" || !current.LeaseValid || current.LastError != nil {
						t.Fatalf("unknown control failure turned terminal: status=%d job=%+v", lastCode, current)
					}
				}
				t.Logf("%s: complete status=%d state=%s; no trusted artifact", loss, lastCode, current.State)
				return
			}

			for deadline := time.Now().Add(2500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
				if code := post("heartbeat", map[string]any{"lease_seconds": 2}); code != 200 {
					t.Fatalf("heartbeat=%d", code)
				}
				if code := post("complete", map[string]any{"manifest_sha256": publication.SHA}); code != 202 {
					t.Fatalf("pending poll=%d", code)
				}
			}
			if _, err = os.Stat(marker); err != nil {
				t.Fatal("private verifier never started", err)
			}
			status, err := repo.Status(ctx, job)
			must(err)
			if status.Attempt != 1 || !status.LeaseValid {
				t.Fatal("pending HTTP stole lease", status.State, status.Attempt)
			}
			if loss == "cancel" {
				// This is the same independently owned recovery loop started
				// by the explicit unified Go entrypoint, not a Worker ACK.
				recoveryContext, stopRecovery := context.WithCancel(context.Background())
				recoveryDone := make(chan struct{})
				go func() {
					defer close(recoveryDone)
					repo.RunRecovery(recoveryContext, control, 100*time.Millisecond, nil)
				}()
				defer func() { stopRecovery(); <-recoveryDone }()
				if code := post("cancel", nil); code != 200 {
					t.Fatalf("HTTP cancel=%d", code)
				}
				if err = repo.AcknowledgeCancel(ctx, claim); !errors.Is(err, jobs.ErrStale) {
					t.Fatalf("cancel ACK before verifier exit=%v", err)
				}
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				var state string
				must(db.QueryRow("SELECT state FROM m4_compact_verifications WHERE job_id=$1", job).Scan(&state))
				if state == "exited" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("verifier did not remove and release durable slot")
				}
				time.Sleep(50 * time.Millisecond)
			}
			if _, err = os.Stat(marker + ".removed"); err != nil {
				t.Fatal("verifier cleanup not proven", err)
			}
			if loss == "cancel" {
				// The unchanged five-second recovery delay and both exit
				// predicates must pass before cancellation becomes terminal.
				closureDeadline := time.Now().Add(7 * time.Second)
				for {
					current, e := repo.Status(ctx, job)
					must(e)
					if current.State == "cancelled" {
						break
					}
					if time.Now().After(closureDeadline) {
						t.Fatalf("automatic cancellation closure stalled at %s", current.State)
					}
					time.Sleep(50 * time.Millisecond)
				}
			}

			receipts, err := filepath.Glob(filepath.Join(control, "compact-verification-*.json"))
			must(err)
			if len(receipts) != 1 {
				t.Fatal("missing verifier receipt")
			}
			receiptRaw, err := os.ReadFile(receipts[0])
			must(err)
			var receipt struct {
				Watcher map[string]any `json:"watcher_cancellation"`
			}
			must(json.Unmarshal(receiptRaw, &receipt))
			wanted := "lease_expired"
			if loss == "cancel" {
				wanted = "state_changed"
			}
			if receipt.Watcher["reason"] != wanted {
				t.Fatalf("watcher reason=%v expected=%s", receipt.Watcher, wanted)
			}
			if err = repo.Complete(ctx, claim, base+publication.SHA+".json", publication.SHA); !errors.Is(err, jobs.ErrStale) {
				t.Fatalf("late stale publication=%v", err)
			}
			t.Logf("2s lease sustained through delayed verifier, then %s removed verifier and rejected late publication", loss)
		})
	}
}

func sum(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }
