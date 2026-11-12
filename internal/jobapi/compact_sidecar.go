package jobapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Only the Go service and its read-only verifier share this socket volume.
func (s *Server) compactSidecarVerify(ctx context.Context, base, sha string, request map[string]any, key [32]byte) ([]byte, error) {
	parts := strings.Split(strings.Trim(base, "/"), "/")
	if len(parts) != 3 {
		return nil, errors.New("invalid verifier path")
	}
	job := parts[1]
	var attempt int
	if _, err := fmt.Sscanf(parts[2], "attempt-%d", &attempt); err != nil {
		return nil, err
	}
	st, err := s.Repo.Status(ctx, job)
	if err != nil {
		return nil, err
	}
	terminal := st.State == "succeeded"
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(nonce[:])
	claimed, err := s.Repo.BeginCompactVerification(ctx, job, attempt, id, terminal)
	if err != nil {
		return nil, err
	}
	deadline := claimed.Add(1800 * time.Second)
	if terminal {
		deadline = time.Now().Add(1800 * time.Second)
	}
	seconds := int(time.Until(deadline).Seconds())
	if seconds < 1 {
		if err = s.Repo.FinishCompactVerification(ctx, job, attempt, id); err != nil {
			return nil, err
		}
		return nil, context.DeadlineExceeded
	}
	request["seconds"] = seconds
	envelope := map[string]any{"request": request, "authority_key": hex.EncodeToString(key[:])}
	compose := os.Getenv("CPAG_VERIFY_BACKEND") == "compose-file-sidecar-v1"
	if compose {
		envelope["verifier_identity"] = s.CompactVerifierImage
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(c, "unix", "/verify-channel/source.sock")
	}, DisableKeepAlives: true}
	client := http.Client{Transport: transport, Timeout: time.Until(deadline) + 5*time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://verifier/verify", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	} // ambiguous execution; keep the durable slot
	defer resp.Body.Close()
	if compose && resp.Header.Get("X-CPAG-Verifier-Identity") != s.CompactVerifierImage {
		return nil, errors.New("Compose source verifier identity mismatch")
	}
	result, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if err != nil || len(result) > 8<<20 {
		return nil, errors.New("invalid verifier response")
	}
	receipt := map[string]any{"version": "service-sidecar-verification-2", "verification_id": id, "run_id": job, "attempt_id": attempt, "publication_sha256": sha, "status": resp.StatusCode, "ended_at": time.Now().UTC(), "cleanup_completed": true}
	if compose {
		receipt["verifier_source_identity"] = s.CompactVerifierImage
	}
	if err = s.saveCompactReceipt(job, attempt, id, receipt); err != nil {
		return nil, err
	}
	if err = s.Repo.FinishCompactVerification(ctx, job, attempt, id); err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("source verifier rejected: %s", result)
	}
	current, err := s.Repo.Status(ctx, job)
	if err != nil || current.Attempt != attempt || (!terminal && (current.State != "running" || !current.LeaseValid)) || (terminal && current.State != "succeeded") {
		return nil, jobs.ErrStale
	}
	return result, nil
}
