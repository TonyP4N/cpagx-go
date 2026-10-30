package jobapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/jobs"
)

func ValidCompactVerifierImage(image string) bool {
	if strings.HasPrefix(image, "sha256:") {
		return shaPattern.MatchString(strings.TrimPrefix(image, "sha256:"))
	}
	i := strings.LastIndex(image, "@sha256:")
	return i > 0 && shaPattern.MatchString(image[i+8:])
}
func dockerControl(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	output := &boundedCLIOutput{maximum: 65536}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("compact Docker control failed: %s", strings.TrimSpace(output.String()))
	}
	return output.Bytes(), nil
}
func (s *Server) removeCompactVerifier(id, job string, attempt int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if !shaPattern.MatchString(id) {
		return errors.New("invalid verifier container identity")
	}
	raw, err := dockerControl(ctx, "inspect", id)
	if err != nil {
		return err
	}
	var values []struct {
		ID     string `json:"Id"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if json.Unmarshal(raw, &values) != nil || len(values) != 1 || values[0].ID != id || values[0].Config.Image != s.CompactVerifierImage || values[0].Config.Labels["cpag.role"] != "dag6-source-verifier" || values[0].Config.Labels["cpag.job"] != job || values[0].Config.Labels["cpag.attempt"] != fmt.Sprint(attempt) {
		return errors.New("compact verifier ownership inspection mismatch")
	}
	_, err = dockerControl(ctx, "rm", "--force", id)
	return err
}

// Only exact, inspected service-owned immutable containers may be cleaned up.
// Docker unavailability leaves the durable slot outstanding and startup fails.
func (s *Server) RecoverCompactVerifiers(ctx context.Context) error {
	rows, err := s.Repo.DB.QueryContext(ctx, `SELECT job_id,attempt,container_name FROM m4_compact_verifications WHERE state='running'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type record struct {
		id        string
		attempt   int
		container string
	}
	items := []record{}
	for rows.Next() {
		var r record
		if err = rows.Scan(&r.id, &r.attempt, &r.container); err != nil {
			return err
		}
		items = append(items, r)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, r := range items {
		if err = s.removeCompactVerifier(r.container, r.id, r.attempt); err != nil {
			return err
		}
		if err = s.Repo.FinishCompactVerification(ctx, r.id, r.attempt, r.container); err != nil {
			return err
		}
	}
	return nil
}
func (s *Server) compactDockerVerify(ctx context.Context, base string, p Payload, sha string, request map[string]any, key [32]byte) ([]byte, error) {
	if !ValidCompactVerifierImage(s.CompactVerifierImage) {
		return nil, errors.New("compact verification requires immutable operator Docker image")
	}
	root, err := s.file(strings.TrimSuffix(base, "/"))
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.Trim(base, "/"), "/")
	job := parts[1]
	attempt := 0
	fmt.Sscanf(parts[2], "attempt-%d", &attempt)
	args := []string{"create", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--cpus", "4", "--memory", "8g", "--memory-swap", "8g", "--pids-limit", "64", "--tmpfs", "/tmp:rw,nosuid,nodev,size=4g", "--mount", "type=bind,src=" + root + ",dst=/artifact,readonly", "--label", "cpag.role=dag6-source-verifier", "--label", "cpag.job=" + job, "--label", "cpag.attempt=" + fmt.Sprint(attempt), "--interactive", "--env", "CPAG_PHASE_METRICS=/tmp/verifier-phases.jsonl", "--env", "CPAG_PHASE_STRATEGY=phase-resources-3", "--entrypoint", "python", s.CompactVerifierImage, "-m", "cpag_core.shared_service", "--key-stdin"}
	createdAt := time.Now().UTC()
	raw, err := dockerControl(ctx, args...)
	if err != nil {
		return nil, err
	}
	container := strings.TrimSpace(string(raw))
	if !shaPattern.MatchString(container) {
		return nil, errors.New("Docker omitted immutable verifier identity")
	}
	st, err := s.Repo.Status(ctx, job)
	if err != nil {
		return nil, err
	}
	terminal := st.State == "succeeded"
	claimed, err := s.Repo.BeginCompactVerification(ctx, job, attempt, container, terminal)
	if err != nil {
		s.removeCompactVerifier(container, job, attempt)
		return nil, err
	}
	// The trusted persistent attempt claim clock includes export. Reverification
	// after a server restart gets its own bounded diagnostic budget.
	deadline := claimed.Add(1800 * time.Second)
	if terminal {
		deadline = time.Now().Add(1800 * time.Second)
	}
	runctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	request["output_dir"] = "/artifact"
	request["seconds"] = int(time.Until(deadline).Seconds())
	if request["seconds"].(int) < 1 {
		err = errors.New("compact core 1800 second budget exhausted")
	}
	envelope := map[string]any{"authority_key": hex.EncodeToString(key[:]), "request": request}
	stdin, _ := json.Marshal(envelope)
	watchDone := make(chan struct{})
	watchReason := make(chan map[string]any, 1)
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-runctx.Done():
				return
			case <-ticker.C:
				current, e := s.Repo.Status(runctx, job)
				if reason := compactVerifierWatchReason(current, attempt, terminal, e); reason != "" {
					event := map[string]any{"reason": reason, "observed_at": time.Now().UTC(), "expected_attempt": attempt, "actual_attempt": current.Attempt, "state": current.State, "lease_valid": current.LeaseValid}
					if e != nil {
						event["database_error_type"] = fmt.Sprintf("%T", e)
					}
					watchReason <- event
					cancel()
					return
				}
			}
		}
	}()
	stdout, stderr := &boundedCLIOutput{maximum: 8 << 20}, &boundedCLIOutput{maximum: 65536}
	executionStarted := time.Now().UTC()
	if err == nil {
		cmd := exec.CommandContext(runctx, "docker", "start", "--attach", "--interactive", container)
		cmd.Stdin = bytes.NewReader(stdin)
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		cmd.WaitDelay = time.Second
		err = cmd.Run()
	}
	close(watchDone)
	executionEnded := time.Now().UTC()
	receipt := map[string]any{"version": "service-compact-verification-execution-1", "run_id": job, "attempt_id": attempt, "container_id": container, "image": s.CompactVerifierImage, "created_at": createdAt, "started_at": executionStarted, "ended_at": executionEnded, "wall_seconds": executionEnded.Sub(executionStarted).Seconds(), "trusted_claimed_at": claimed, "core_deadline": deadline, "publication_sha256": sha, "restart_reverification": terminal, "cleanup_completed": false}
	if err != nil {
		receipt["execution_error"] = err.Error()
	}
	select {
	case event := <-watchReason:
		receipt["watcher_cancellation"] = event
	default:
	}
	if runctx.Err() != nil {
		receipt["execution_context_error"] = runctx.Err().Error()
	}
	var helper map[string]json.RawMessage
	if json.Unmarshal(stdout.Bytes(), &helper) == nil {
		for _, name := range []string{"verification_report", "execution_metrics"} {
			if value, ok := helper[name]; ok {
				receipt[name] = value
			}
		}
	}
	inspectContext, inspectCancel := context.WithTimeout(context.Background(), 10*time.Second)
	inspection, inspectErr := dockerControl(inspectContext, "inspect", container)
	helperExitedNonzero := false
	inspectCancel()
	if inspectErr != nil {
		receipt["inspection_error"] = inspectErr.Error()
	} else {
		var values []struct {
			ID         string         `json:"Id"`
			State      map[string]any `json:"State"`
			HostConfig struct {
				NanoCPUs       int64             `json:"NanoCpus"`
				Memory         int64             `json:"Memory"`
				MemorySwap     int64             `json:"MemorySwap"`
				ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
				NetworkMode    string            `json:"NetworkMode"`
				Tmpfs          map[string]string `json:"Tmpfs"`
			} `json:"HostConfig"`
		}
		if json.Unmarshal(inspection, &values) == nil && len(values) == 1 {
			receipt["docker_inspection"] = values[0]
			running, runningKnown := values[0].State["Running"].(bool)
			exitCode, exitKnown := values[0].State["ExitCode"].(float64)
			oom, oomKnown := values[0].State["OOMKilled"].(bool)
			helperExitedNonzero = values[0].ID == container && runningKnown && !running && exitKnown && exitCode > 0 && oomKnown && !oom && values[0].State["Status"] == "exited"
		}
	}
	receiptErr := s.saveCompactReceipt(job, attempt, container, receipt)
	// Killing the Docker client does not prove that its container exited. Remove
	// the exact inspected container before freeing the durable capacity record.
	cleanupErr := s.removeCompactVerifier(container, job, attempt)
	if cleanupErr != nil {
		receipt["cleanup_error"] = cleanupErr.Error()
		s.saveCompactReceipt(job, attempt, container, receipt)
		return nil, cleanupErr
	}
	receipt["cleanup_completed"] = true
	if e := s.saveCompactReceipt(job, attempt, container, receipt); receiptErr == nil {
		receiptErr = e
	}
	if finishErr := s.Repo.FinishCompactVerification(context.Background(), job, attempt, container); finishErr != nil {
		return nil, finishErr
	}
	if receiptErr != nil {
		return nil, receiptErr
	}
	if err != nil {
		if runctx.Err() != nil {
			return nil, runctx.Err()
		}
		if inspectErr == nil {
			if rejection := compactPermanentVerificationFailure(err, helperExitedNonzero, stderr.Bytes()); rejection != nil {
				return nil, rejection
			}
		}
		return nil, fmt.Errorf("compact isolated source verification failed: %s", strings.TrimSpace(stderr.String()))
	}
	current, err := s.Repo.Status(ctx, job)
	if err != nil || current.Attempt != attempt || (!terminal && (current.State != "running" || !current.LeaseValid)) || (terminal && current.State != "succeeded") {
		return nil, jobs.ErrStale
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

func (s *Server) saveCompactReceipt(job string, attempt int, container string, receipt map[string]any) error {
	if !identity.MatchString(job) || !shaPattern.MatchString(container) || s.ControlRoot == "" {
		return errors.New("private compact execution receipt root required")
	}
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return errors.New("compact execution receipt exceeds bound")
	}
	temporary, err := os.CreateTemp(s.ControlRoot, "compact-receipt-")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err = temporary.Write(append(raw, '\n')); err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(temporary.Name(), filepath.Join(s.ControlRoot, fmt.Sprintf("compact-verification-%s-%d-%s.json", job, attempt, container[:12])))
}

// Fixed diagnostic reasons preserve which ownership guard cancelled control work.
// No token, payload, source content or caller-controlled error text is recorded.
func compactVerifierWatchReason(status jobs.Status, attempt int, terminal bool, err error) string {
	if err != nil {
		return "database_status_error"
	}
	if status.Attempt != attempt {
		return "attempt_changed"
	}
	if terminal {
		if status.State != "succeeded" {
			return "terminal_state_changed"
		}
		return ""
	}
	if status.State != "running" {
		return "state_changed"
	}
	if !status.LeaseValid {
		return "lease_expired"
	}
	return ""
}
