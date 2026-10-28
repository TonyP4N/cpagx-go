package catalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/capacity"
	"github.com/TonyP4N/cpagx-go/internal/jobapi"
)

const evaluationProjectionLimit = 8 << 20

func evaluationResourceProjectionLimit(resource, operator string) (int, error) {
	if resource != operator {
		return 0, errors.New("evaluation resource profile differs from operator policy")
	}
	switch resource {
	case "":
		return evaluationProjectionLimit, nil
	case capacity.DevelopmentS100, capacity.Engineering:
		return evaluationV2DocumentLimit, nil
	default:
		return 0, errors.New("unsupported evaluation resource profile")
	}
}

// evaluationInput is only a read-only projection of a verified publication.
// Dataset ACL authorization is performed by serveRuns before entering here.
// It does not accept annotations, run analysis, freeze or publish an evaluation.
func (s *Server) evaluationInput(w http.ResponseWriter, r *http.Request, p *principal, dataset, id, mode string) {
	query, queryErr := url.ParseQuery(r.URL.RawQuery)
	if queryErr != nil {
		fail(w, 422, "invalid_evaluation_projection", "invalid query encoding")
		return
	}
	projection := "dual"
	for key, values := range query {
		if key != "projection" || len(values) != 1 {
			fail(w, 422, "invalid_evaluation_projection", "only one projection parameter is supported")
			return
		}
		projection = values[0]
	}
	if projection != "network" && projection != "process" && projection != "dual" {
		fail(w, 422, "invalid_evaluation_projection", "projection must be network, process or dual")
		return
	}
	if mode != "dual_source" && mode != "dual_source_replay" {
		fail(w, 409, "evaluation_input_unavailable", "verified dual or replay publication required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	internal, ok := s.Internal.(*jobapi.Server)
	if !ok {
		fail(w, 503, "evaluation_adapter_unavailable", "evaluation adapter unavailable")
		return
	}
	items, base, err := internal.VerifiedDualArtifacts(r, id) // also verifies replay publications
	if err != nil {
		fail(w, 409, "evaluation_input_unavailable", "published artifacts unavailable or changed")
		return
	}
	status, err := internal.Repo.Status(ctx, id)
	var payload jobapi.Payload
	if err != nil || json.Unmarshal(status.Payload, &payload) != nil {
		fail(w, 409, "evaluation_input_unavailable", "published resource policy unavailable")
		return
	}
	projectionLimit, err := evaluationResourceProjectionLimit(payload.ResourceProfile, s.cfg.ResourceProfile)
	if err != nil {
		fail(w, 409, "evaluation_input_unavailable", "published resource policy differs")
		return
	}
	var batch string
	if err = s.DB.QueryRowContext(ctx, "SELECT batch FROM v3_datasets WHERE id=$1", dataset).Scan(&batch); err != nil || strings.TrimSpace(batch) == "" {
		fail(w, 409, "evaluation_context_unavailable", "dataset batch unavailable")
		return
	}
	var core struct {
		RunID   string `json:"run_id"`
		Input   string `json:"input_fingerprint"`
		Config  string `json:"config_fingerprint"`
		Attempt int    `json:"attempt_id"`
		Mode    string `json:"mode"`
	}
	var coreSHA string
	for _, item := range items {
		if item.Path != "run_manifest.json" || item.Size < 0 || item.Size > evaluationProjectionLimit {
			continue
		}
		file, readErr := os.Open(filepath.Join(s.Root, base, item.Path))
		if readErr != nil {
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, evaluationProjectionLimit+1))
		file.Close()
		sum := sha256.Sum256(raw)
		if readErr == nil && int64(len(raw)) == item.Size && hex.EncodeToString(sum[:]) == item.SHA && json.Unmarshal(raw, &core) == nil {
			coreSHA = item.SHA
		}
	}
	expectedMode := "offline"
	if mode == "dual_source_replay" {
		expectedMode = "replay"
	}
	if coreSHA == "" || core.RunID != id || core.Attempt < 1 || core.Mode != expectedMode || !shaRE.MatchString(core.Input) || !shaRE.MatchString(core.Config) {
		fail(w, 409, "evaluation_input_unavailable", "published identity unavailable or changed")
		return
	}
	raw, err := s.runEvaluationProjection(ctx, filepath.Join(s.Root, base), batch, core.Input, projection, projectionLimit)
	if err != nil {
		fail(w, 409, "evaluation_projection_failed", "bounded evaluation projection unavailable")
		return
	}
	var result struct {
		Binding struct {
			RunID      string            `json:"run_id"`
			Attempt    int               `json:"attempt_id"`
			Input      string            `json:"input_fingerprint"`
			Config     string            `json:"config_fingerprint"`
			Projection string            `json:"projection"`
			Batch      string            `json:"batch"`
			Sample     string            `json:"sample_sha256"`
			Hashes     map[string]string `json:"artifact_sha256"`
		} `json:"binding"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Binding.RunID != id || result.Binding.Attempt != core.Attempt || result.Binding.Input != core.Input || result.Binding.Config != core.Config || result.Binding.Projection != projection || result.Binding.Batch != batch || result.Binding.Sample != core.Input || result.Binding.Hashes["run_manifest.json"] != coreSHA {
		fail(w, 409, "evaluation_projection_failed", "evaluation projection identity changed")
		return
	}
	// Re-check the current published attempt after the adapter reads it. A retry,
	// restored or changed publication cannot borrow the first check's authority.
	after, afterBase, err := internal.VerifiedDualArtifacts(r, id)
	if err != nil || afterBase != base || !reflect.DeepEqual(after, items) {
		fail(w, 409, "evaluation_input_unavailable", "published artifacts changed during projection")
		return
	}
	if s.audit(ctx, p, dataset, id, "evaluation_input_read", "ok") != nil {
		fail(w, 503, "audit_unavailable", "evaluation projection audit unavailable")
		return
	}
	respond(w, 200, json.RawMessage(raw))
}

// A failed/oversized child output is never returned as a partial projection.
// stdout and stderr have separate caps; diagnostic text is not sent to clients.
type evaluationBuffer struct {
	bytes.Buffer
	limit int
}

func (b *evaluationBuffer) Write(value []byte) (int, error) {
	if len(value) > b.limit-b.Len() {
		return 0, errors.New("evaluation adapter output exceeds limit")
	}
	return b.Buffer.Write(value)
}

func (s *Server) runEvaluationProjection(ctx context.Context, artifact, batch, sample, projection string, limits ...int) ([]byte, error) {
	limit := evaluationProjectionLimit
	if len(limits) > 1 {
		return nil, errors.New("one evaluation projection budget required")
	}
	if len(limits) == 1 {
		limit = limits[0]
	}
	if limit != evaluationProjectionLimit && limit != evaluationV2DocumentLimit {
		return nil, errors.New("unsupported evaluation projection budget")
	}
	cmd := exec.CommandContext(ctx, s.cfg.PythonBin, "-m", "cpag_core.evaluation_artifacts", "--artifact", artifact, "--batch", batch, "--sample-sha256", sample, "--projection", projection)
	cmd.Env = os.Environ()
	if s.cfg.PythonPath != "" {
		cmd.Env = append(cmd.Env, "PYTHONPATH="+s.cfg.PythonPath)
	}
	cmd.WaitDelay = time.Second
	out := &evaluationBuffer{limit: limit}
	diagnostics := &evaluationBuffer{limit: 8192}
	cmd.Stdout, cmd.Stderr = out, diagnostics
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(out.Bytes()))
	var value map[string]any
	if decoder.Decode(&value) != nil || value == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid evaluation projection output")
	}
	return out.Bytes(), nil
}
