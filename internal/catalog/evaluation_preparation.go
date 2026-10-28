package catalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/jobapi"
)

const preparationVersion = "evaluation-preparation-1"
const preparationBudget int64 = 1 << 30
const preparationLock int64 = 19002802
const preparationBytesLock int64 = 19002803

// Only service-written rows can become ready. The HTTP request chooses a
// projection, never a hash, owner, inventory, document, or verification policy.
type evaluationPreparation struct {
	ID                 string          `json:"id"`
	Job                string          `json:"run_id"`
	Dataset            string          `json:"-"`
	Attempt            int             `json:"attempt"`
	PayloadSHA         string          `json:"-"`
	PublicationSHA     string          `json:"publication_sha256"`
	ArtifactPath       string          `json:"-"`
	Config             string          `json:"config_fingerprint"`
	Input              sql.NullString  `json:"-"`
	Batch              string          `json:"batch"`
	Projection         string          `json:"projection"`
	Strategy           string          `json:"strategy_version"`
	State              string          `json:"state"`
	PreparationAttempt int             `json:"preparation_attempt"`
	Owner              string          `json:"-"`
	Reason             string          `json:"reason_code"`
	Limit              int             `json:"-"`
	Document           []byte          `json:"-"`
	DocumentSHA        sql.NullString  `json:"-"`
	DocumentSize       int64           `json:"document_size"`
	Inventory          []byte          `json:"-"`
	Cost               json.RawMessage `json:"cost"`
}

const preparationColumns = `id,job_id,dataset_id,attempt,payload_sha256,publication_sha256,artifact_path,config_fingerprint,input_fingerprint,batch,projection,strategy_version,state,preparation_attempt,owner,reason_code,document_limit,document_bytes,document_sha256,document_size,inventory_json,cost_json`

func scanPreparation(row interface{ Scan(...any) error }) (p evaluationPreparation, err error) {
	err = row.Scan(&p.ID, &p.Job, &p.Dataset, &p.Attempt, &p.PayloadSHA, &p.PublicationSHA, &p.ArtifactPath, &p.Config, &p.Input, &p.Batch, &p.Projection, &p.Strategy, &p.State, &p.PreparationAttempt, &p.Owner, &p.Reason, &p.Limit, &p.Document, &p.DocumentSHA, &p.DocumentSize, &p.Inventory, &p.Cost)
	return
}
func (p evaluationPreparation) public() map[string]any {
	result := map[string]any{"id": p.ID, "run_id": p.Job, "attempt": p.Attempt, "source_attempt": p.Attempt, "projection": p.Projection, "strategy_version": p.Strategy, "state": p.State, "reason_code": p.Reason, "preparation_attempt": p.PreparationAttempt, "publication_sha256": p.PublicationSHA, "document_size": p.DocumentSize, "cost": p.Cost}
	if p.DocumentSHA.Valid {
		result["document_sha256"] = p.DocumentSHA.String
	}
	var cost map[string]any
	if json.Unmarshal(p.Cost, &cost) == nil {
		if duration, ok := cost["total_seconds"]; ok {
			result["duration_seconds"] = duration
		}
	}
	return result
}
func validPreparationProjection(value string) bool {
	return value == "network" || value == "process" || value == "dual"
}
func (s *Server) latestPreparation(ctx context.Context, id, projection string) (evaluationPreparation, error) {
	return scanPreparation(s.DB.QueryRowContext(ctx, "SELECT "+preparationColumns+" FROM v3_evaluation_preparations WHERE job_id=$1 AND projection=$2 ORDER BY created_at DESC,id DESC LIMIT 1", id, projection))
}

func (s *Server) evaluationPreparation(w http.ResponseWriter, r *http.Request, p *principal, dataset, id, mode string) {
	if mode != "dual_source" && mode != "dual_source_replay" {
		fail(w, 409, "evaluation_preparation_unavailable", "verified dual publication required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	projection := "dual"
	if r.Method == "POST" {
		if !s.can(ctx, p, dataset, true) {
			fail(w, 403, "forbidden", "dataset write access required")
			return
		}
		var request struct {
			Projection string `json:"projection"`
		}
		if r.URL.RawQuery != "" || body(w, r, &request, 1024) != nil {
			fail(w, 422, "invalid_evaluation_projection", "only projection is accepted")
			return
		}
		if request.Projection != "" {
			projection = request.Projection
		}
	} else if r.Method == "GET" {
		query, err := strictProjectionQuery(r)
		if err != nil {
			fail(w, 422, "invalid_evaluation_projection", "only one projection is accepted")
			return
		}
		projection = query
	} else {
		fail(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	if !validPreparationProjection(projection) {
		fail(w, 422, "invalid_evaluation_projection", "projection must be network, process or dual")
		return
	}
	if r.Method == "POST" {
		internal, ok := s.Internal.(*jobapi.Server)
		if !ok {
			fail(w, 503, "evaluation_adapter_unavailable", "adapter unavailable")
			return
		}
		st, err := internal.Repo.Status(ctx, id)
		if err != nil || st.State != "succeeded" || st.ArtifactPath == nil || st.ArtifactSHA256 == nil {
			fail(w, 409, "evaluation_preparation_unavailable", "successful current publication required")
			return
		}
		var payload jobapi.Payload
		payloadSHA, err := jobapi.DualProfileFingerprint(st.Payload)
		if err != nil || json.Unmarshal(st.Payload, &payload) != nil {
			fail(w, 409, "evaluation_preparation_unavailable", "publication payload unavailable")
			return
		}
		limit, err := evaluationResourceProjectionLimit(payload.ResourceProfile, s.cfg.ResourceProfile)
		if err != nil {
			fail(w, 409, "evaluation_preparation_unavailable", "resource policy unavailable")
			return
		}
		var batch string
		if s.DB.QueryRowContext(ctx, "SELECT batch FROM v3_datasets WHERE id=$1", dataset).Scan(&batch) != nil || strings.TrimSpace(batch) == "" {
			fail(w, 409, "evaluation_preparation_unavailable", "dataset batch unavailable")
			return
		}
		key, _ := json.Marshal([]any{preparationVersion, id, st.Attempt, payloadSHA, *st.ArtifactSHA256, batch, projection})
		digest := sha256.Sum256(key)
		prepID := fmt.Sprintf("%x", digest[:])
		// Retrying a failed row preserves every prior attempt in the side table.
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			fail(w, 503, "evaluation_preparation_unavailable", "preparation transaction unavailable")
			return
		}
		defer tx.Rollback()
		_, err = tx.ExecContext(ctx, `INSERT INTO v3_evaluation_preparations(id,job_id,dataset_id,attempt,payload_sha256,publication_sha256,artifact_path,config_fingerprint,batch,projection,strategy_version,state,document_limit) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'queued',$12) ON CONFLICT(id) DO UPDATE SET state=CASE WHEN v3_evaluation_preparations.state='failed' AND v3_evaluation_preparations.preparation_attempt<100 THEN 'queued' ELSE v3_evaluation_preparations.state END,updated_at=clock_timestamp()`, prepID, id, dataset, st.Attempt, payloadSHA, *st.ArtifactSHA256, *st.ArtifactPath, payload.Fingerprint, batch, projection, preparationVersion, limit)
		if err != nil {
			fail(w, 503, "evaluation_preparation_unavailable", "preparation queue unavailable")
			return
		}
		if auditTx(ctx, tx, p, dataset, id, "evaluation_preparation_request", "accepted") != nil || tx.Commit() != nil {
			fail(w, 503, "audit_unavailable", "preparation audit unavailable")
			return
		}
		select {
		case s.preparationWake <- struct{}{}:
		default:
		}
	}
	row, err := s.latestPreparation(ctx, id, projection)
	if err == sql.ErrNoRows {
		fail(w, 404, "evaluation_preparation_not_found", "preparation not requested")
		return
	}
	if err != nil {
		fail(w, 503, "evaluation_preparation_unavailable", "preparation status unavailable")
		return
	}
	if row.State == "ready" {
		if _, _, err = s.checkPrepared(r, row); err != nil {
			fail(w, 409, "evaluation_preparation_source_changed", "prepared source unavailable or changed")
			return
		}
	}
	if r.Method == "GET" && s.audit(ctx, p, dataset, id, "evaluation_preparation_read", "ok") != nil {
		fail(w, 503, "audit_unavailable", "preparation read audit unavailable")
		return
	}
	status := 200
	if r.Method == "POST" && row.State != "ready" {
		status = 202
	}
	public := row.public()
	if reason := s.preparationCoordinatorReason(); reason != "" {
		public["coordinator_reason"] = reason
	}
	respond(w, status, map[string]any{"preparation": public})
}
func strictProjectionQuery(r *http.Request) (string, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", err
	}
	value := "dual"
	for key, values := range query {
		if key != "projection" || len(values) != 1 {
			return "", errors.New("invalid projection query")
		}
		value = values[0]
	}
	if !validPreparationProjection(value) {
		return "", errors.New("invalid projection")
	}
	return value, nil
}

func validatePreparedDocument(raw []byte, p evaluationPreparation, snapshot jobapi.PublicationSnapshot) error {
	if len(raw) == 0 || len(raw) > p.Limit || validateUniqueJSON(raw) != nil {
		return errors.New("prepared JSON outside budget")
	}
	var doc struct {
		Binding struct {
			Run        string            `json:"run_id"`
			Attempt    int               `json:"attempt_id"`
			Input      string            `json:"input_fingerprint"`
			Config     string            `json:"config_fingerprint"`
			Batch      string            `json:"batch"`
			Sample     string            `json:"sample_sha256"`
			Projection string            `json:"projection"`
			Mode       string            `json:"mode"`
			Hashes     map[string]string `json:"artifact_sha256"`
		} `json:"binding"`
		Predictions struct {
			Run    string `json:"run_id"`
			Input  string `json:"input_fingerprint"`
			Config string `json:"config_fingerprint"`
		} `json:"predictions"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return errors.New("invalid prepared projection")
	}
	b := doc.Binding
	if b.Run != p.Job || b.Attempt != p.Attempt || b.Input != snapshot.InputFingerprint || b.Config != p.Config || b.Batch != p.Batch || b.Sample != b.Input || b.Projection != p.Projection || b.Mode != snapshot.Mode || doc.Predictions.Run != p.Job || doc.Predictions.Input != b.Input || doc.Predictions.Config != b.Config || len(b.Hashes) != len(snapshot.Files) {
		return errors.New("prepared projection identity mismatch")
	}
	for _, file := range snapshot.Files {
		if b.Hashes[file.Path] != file.SHA {
			return errors.New("prepared projection artifact mismatch")
		}
	}
	return nil
}
func (s *Server) checkPrepared(r *http.Request, p evaluationPreparation) ([]byte, jobapi.PublicationSnapshot, error) {
	var snapshot jobapi.PublicationSnapshot
	if p.Strategy != preparationVersion || (p.Limit != evaluationProjectionLimit && p.Limit != evaluationV2DocumentLimit) || p.State != "ready" || !p.DocumentSHA.Valid || !p.Input.Valid || p.DocumentSize != int64(len(p.Document)) || p.DocumentSize > int64(p.Limit) || p.DocumentSize > evaluationV2DocumentLimit {
		return nil, snapshot, errors.New("preparation is not ready")
	}
	hash := sha256.Sum256(p.Document)
	if fmt.Sprintf("%x", hash[:]) != p.DocumentSHA.String {
		return nil, snapshot, errors.New("prepared projection byte hash mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(p.Inventory))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&snapshot) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, snapshot, errors.New("invalid prepared inventory")
	}
	if snapshot.RunID != p.Job || snapshot.Attempt != p.Attempt || snapshot.PayloadSHA256 != p.PayloadSHA || snapshot.PublicationSHA256 != p.PublicationSHA || snapshot.ArtifactPath != p.ArtifactPath || snapshot.ConfigFingerprint != p.Config || snapshot.InputFingerprint != p.Input.String {
		return nil, snapshot, errors.New("prepared inventory row identity mismatch")
	}
	var batch string
	if err := s.DB.QueryRowContext(r.Context(), "SELECT d.batch FROM v3_datasets d JOIN v3_run_bindings b ON b.dataset_id=d.id WHERE b.job_id=$1 AND d.id=$2", p.Job, p.Dataset).Scan(&batch); err != nil || batch != p.Batch {
		return nil, snapshot, errors.New("prepared registration context changed")
	}
	internal, ok := s.Internal.(*jobapi.Server)
	if !ok {
		return nil, snapshot, errors.New("adapter unavailable")
	}
	if _, _, err := internal.RecheckPublicationSnapshot(r, p.Job, snapshot); err != nil {
		return nil, snapshot, err
	}
	if err := validatePreparedDocument(p.Document, p, snapshot); err != nil {
		return nil, snapshot, err
	}
	return p.Document, snapshot, nil
}

// This internal lookup never accepts a client-supplied approval or source hash.
func (s *Server) trustedPreparedAdapted(r *http.Request, id, projection string) ([]byte, *jobapi.PublicationSnapshot, bool, error) {
	p, err := s.latestPreparation(r.Context(), id, projection)
	if err == sql.ErrNoRows {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, true, err
	}
	raw, snapshot, err := s.checkPrepared(r, p)
	return raw, &snapshot, true, err
}
func (s *Server) startPreparationWorker() {
	ctx, cancel := context.WithCancel(context.Background())
	s.preparationCancel = cancel
	s.preparationWake = make(chan struct{}, 1)
	s.preparationDone = make(chan struct{})
	go func() {
		defer close(s.preparationDone)
		timer := time.NewTicker(3 * time.Second)
		defer timer.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			s.preparePending(ctx)
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			case <-s.preparationWake:
			}
		}
	}()
}

// Close stops new preparation work and waits for the current bounded child.
func (s *Server) Close() {
	if s.preparationCancel != nil {
		s.preparationCancel()
		<-s.preparationDone
	}
}
func (s *Server) preparationCoordinatorReason() string {
	s.preparationHealthMu.Lock()
	defer s.preparationHealthMu.Unlock()
	return s.preparationHealthReason
}
func (s *Server) setPreparationCoordinatorReason(reason string, err error) {
	s.preparationHealthMu.Lock()
	changed := s.preparationHealthReason != reason
	s.preparationHealthReason = reason
	s.preparationHealthMu.Unlock()
	if changed && reason != "" {
		log.Printf("evaluation preparation coordinator: %s: %v", reason, err)
	}
}
func (s *Server) preparePending(parent context.Context) {
	conn, err := s.DB.Conn(parent)
	if err != nil {
		s.setPreparationCoordinatorReason("preparation_database_unavailable", err)
		return
	}
	defer conn.Close()
	var locked bool
	if err = conn.QueryRowContext(parent, "SELECT pg_try_advisory_lock($1)", preparationLock).Scan(&locked); err != nil {
		s.setPreparationCoordinatorReason("preparation_database_unavailable", err)
		return
	}
	if !locked {
		s.setPreparationCoordinatorReason("preparation_coordinator_busy", nil)
		return
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(unlockCtx, "SELECT pg_advisory_unlock($1)", preparationLock); err != nil {
			s.setPreparationCoordinatorReason("preparation_unlock_failed", err)
		}
	}()
	lock, err := os.OpenFile(filepath.Join(s.cfg.ControlRoot, "evaluation-preparation.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		s.setPreparationCoordinatorReason("preparation_lock_unavailable", err)
		return
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		s.setPreparationCoordinatorReason("preparation_child_exit_unconfirmed", err)
		return
	}
	// Do not LOCK_UN: an orphan child inherits this open-file description and
	// must retain the lock until real exit, including after SIGKILL of this server.
	host, _ := os.Hostname()
	scope := sha256.Sum256([]byte(host + "\x00" + s.cfg.ControlRoot))
	scopeID := fmt.Sprintf("%x", scope[:])
	var foreign int
	if err = conn.QueryRowContext(parent, "SELECT count(*) FROM v3_evaluation_preparations WHERE state='preparing' AND coordination_scope<>$1", scopeID).Scan(&foreign); err != nil {
		s.setPreparationCoordinatorReason("preparation_database_unavailable", err)
		return
	}
	if foreign > 0 {
		s.setPreparationCoordinatorReason("coordination_scope_mismatch", nil)
		_, err = conn.ExecContext(parent, "UPDATE v3_evaluation_preparations SET reason_code='coordination_scope_mismatch',updated_at=clock_timestamp() WHERE state='preparing' AND coordination_scope<>$1", scopeID)
		if err != nil {
			s.setPreparationCoordinatorReason("preparation_database_unavailable", err)
		}
		return
	}
	s.setPreparationCoordinatorReason("", nil)
	// No inherited child lock survives. Only our private preparation namespace
	// is cleaned; ordinary query or user directories are never removed.
	entries, err := os.ReadDir(s.cfg.ControlRoot)
	if err != nil {
		s.setPreparationCoordinatorReason("preparation_cleanup_unavailable", err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "evaluation-preparation-") {
			work := filepath.Join(s.cfg.ControlRoot, entry.Name())
			if receipt, readErr := os.ReadFile(filepath.Join(work, "guard.jsonl")); readErr == nil && len(receipt) <= 8192 {
				evidence := filepath.Join(s.cfg.ControlRoot, "preparation-evidence")
				if err = os.MkdirAll(evidence, 0700); err == nil {
					err = os.WriteFile(filepath.Join(evidence, entry.Name()+".jsonl"), receipt, 0600)
				}
				if err != nil {
					s.setPreparationCoordinatorReason("preparation_evidence_store_unavailable", err)
					return
				}
			}
			if err = os.RemoveAll(work); err != nil {
				s.setPreparationCoordinatorReason("preparation_cleanup_unavailable", err)
				return
			}
		}
	}
	// Holding both the cross-process DB lease and inherited local lock proves no
	// same-scope child survives before a pending attempt can be recovered.
	tx, err := conn.BeginTx(parent, nil)
	if err != nil {
		s.setPreparationCoordinatorReason("preparation_recovery_failed", err)
		return
	}
	_, err = tx.ExecContext(parent, `UPDATE v3_evaluation_preparation_attempts a SET state='failed',reason_code='service_restarted',finished_at=clock_timestamp(),cost_json=jsonb_build_object('recovery_elapsed_seconds',extract(epoch FROM clock_timestamp()-a.started_at)) FROM v3_evaluation_preparations p WHERE a.preparation_id=p.id AND a.attempt=p.preparation_attempt AND a.state='preparing' AND p.state='preparing' AND p.coordination_scope=$1`, scopeID)
	if err == nil {
		_, err = tx.ExecContext(parent, `UPDATE v3_evaluation_preparations SET state=CASE WHEN preparation_attempt>=100 THEN 'failed' ELSE 'queued' END,owner='',reason_code=CASE WHEN preparation_attempt>=100 THEN 'preparation_retry_limit' ELSE 'service_restarted' END,updated_at=clock_timestamp() WHERE state='preparing' AND coordination_scope=$1`, scopeID)
	}
	if err != nil {
		tx.Rollback()
		s.setPreparationCoordinatorReason("preparation_recovery_failed", err)
		return
	}
	if err = tx.Commit(); err != nil {
		s.setPreparationCoordinatorReason("preparation_recovery_failed", err)
		return
	}
	for parent.Err() == nil {
		p, err := scanPreparation(conn.QueryRowContext(parent, "SELECT "+preparationColumns+" FROM v3_evaluation_preparations WHERE state='queued' AND preparation_attempt<100 ORDER BY created_at,id LIMIT 1"))
		if err != nil {
			if err != sql.ErrNoRows {
				s.setPreparationCoordinatorReason("preparation_queue_unavailable", err)
			}
			return
		}
		owner := newID()
		p.Owner = owner
		p.PreparationAttempt++
		tx, err = conn.BeginTx(parent, nil)
		if err != nil {
			s.setPreparationCoordinatorReason("preparation_claim_failed", err)
			return
		}
		res, err := tx.ExecContext(parent, `UPDATE v3_evaluation_preparations SET state='preparing',preparation_attempt=$2,owner=$3,coordination_scope=$4,reason_code='',error_detail='',started_at=clock_timestamp(),finished_at=NULL,updated_at=clock_timestamp() WHERE id=$1 AND state='queued'`, p.ID, p.PreparationAttempt, owner, scopeID)
		if err == nil {
			n, _ := res.RowsAffected()
			if n != 1 {
				err = errors.New("preparation claim lost")
			}
		}
		if err == nil {
			_, err = tx.ExecContext(parent, `INSERT INTO v3_evaluation_preparation_attempts(preparation_id,attempt,state,owner) VALUES($1,$2,'preparing',$3)`, p.ID, p.PreparationAttempt, owner)
		}
		if err != nil {
			tx.Rollback()
			s.setPreparationCoordinatorReason("preparation_claim_failed", err)
			return
		}
		if err = tx.Commit(); err != nil {
			s.setPreparationCoordinatorReason("preparation_claim_failed", err)
			return
		}
		s.executePreparation(parent, conn, lock, p)
	}
}
func (s *Server) executePreparation(parent context.Context, conn *sql.Conn, lock *os.File, p evaluationPreparation) {
	start := time.Now()
	cost := map[string]any{"wall_limit_seconds": 1800, "resource_version": "evaluation-preparation-resources-1"}
	ctx, cancel := context.WithTimeout(parent, 1800*time.Second)
	defer cancel()
	temporary, err := os.MkdirTemp(s.cfg.ControlRoot, "evaluation-preparation-")
	if err == nil {
		defer os.RemoveAll(temporary)
		ctx = jobapi.WithPreparationExecution(ctx, lock, temporary)
	}
	var snapshot jobapi.PublicationSnapshot
	var raw []byte
	reason := "preparation_verification_failed"
	internal, ok := s.Internal.(*jobapi.Server)
	phase := time.Now()
	if err == nil && !ok {
		err = errors.New("internal adapter unavailable")
	}
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://internal/", nil)
	if err == nil {
		snapshot, err = internal.CapturePublicationSnapshot(request, p.Job)
	}
	cost["verification_seconds"] = time.Since(phase).Seconds()
	if err == nil && (snapshot.Attempt != p.Attempt || snapshot.PayloadSHA256 != p.PayloadSHA || snapshot.PublicationSHA256 != p.PublicationSHA || snapshot.ConfigFingerprint != p.Config || snapshot.ArtifactPath != p.ArtifactPath) {
		err = errors.New("queued publication identity changed")
	}
	phase = time.Now()
	if err == nil {
		reason = "preparation_projection_failed"
		raw, err = s.runEvaluationProjection(context.WithValue(ctx, evaluationPublicationContextKey{}, snapshot.CoreManifestSHA256), filepath.Join(s.Root, filepath.Dir(snapshot.ArtifactPath)), p.Batch, snapshot.InputFingerprint, p.Projection, p.Limit)
	}
	cost["projection_seconds"] = time.Since(phase).Seconds()
	phase = time.Now()
	if err == nil {
		reason = "preparation_postcheck_failed"
		err = validatePreparedDocument(raw, p, snapshot)
		if err == nil {
			_, _, err = internal.RecheckPublicationSnapshot(request, p.Job, snapshot)
		}
	}
	cost["postcheck_seconds"] = time.Since(phase).Seconds()
	cost["total_seconds"] = time.Since(start).Seconds()
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		reason = "preparation_timeout"
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		reason = "preparation_interrupted"
	}
	// Final CAS uses an independent bounded context so cancellation also records
	// an explicit failure. A killed process is recovered with a new owner later.
	finishParent := context.Background()
	if err == nil {
		finishParent = ctx
	}
	finishCtx, finishCancel := context.WithTimeout(finishParent, 10*time.Second)
	defer finishCancel()
	if guardRaw, readErr := os.ReadFile(filepath.Join(temporary, "guard.jsonl")); readErr == nil && len(guardRaw) <= 8192 {
		records := []json.RawMessage{}
		for _, line := range bytes.Split(guardRaw, []byte("\n")) {
			if len(line) > 0 && json.Valid(line) {
				records = append(records, append(json.RawMessage(nil), line...))
			}
		}
		cost["child_resource_records"] = records
	}
	costRaw, _ := json.Marshal(cost)
	inventory, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(raw)
	digest := fmt.Sprintf("%x", sum[:])
	state := "failed"
	detail := ""
	tx, txErr := conn.BeginTx(finishCtx, nil)
	if txErr != nil {
		s.setPreparationCoordinatorReason("preparation_result_store_unavailable", txErr)
		return
	}
	defer tx.Rollback()
	if err == nil {
		_, err = tx.ExecContext(finishCtx, "SELECT pg_advisory_xact_lock($1)", preparationBytesLock)
		var total int64
		if err == nil {
			err = tx.QueryRowContext(finishCtx, "SELECT COALESCE(sum(document_size),0) FROM v3_evaluation_preparations WHERE state='ready' AND id<>$1", p.ID).Scan(&total)
		}
		if err == nil && !preparationDocumentFits(total, int64(len(raw)), int64(p.Limit)) {
			reason = "preparation_storage_budget_exceeded"
			err = errors.New("prepared document global budget exceeded")
		}
	}
	if err == nil {
		state = "ready"
		reason = ""
	} else {
		detail = err.Error()
		if len(detail) > 8192 {
			detail = detail[:8192]
		}
	}
	var result sql.Result
	if state == "ready" {
		result, txErr = tx.ExecContext(finishCtx, `UPDATE v3_evaluation_preparations SET state='ready',input_fingerprint=$3,document_bytes=$4,document_sha256=$5,document_size=$6,inventory_json=$7,cost_json=$8,reason_code='',error_detail='',finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND owner=$2 AND state='preparing' AND preparation_attempt=$9`, p.ID, p.Owner, snapshot.InputFingerprint, raw, digest, len(raw), inventory, costRaw, p.PreparationAttempt)
	} else {
		result, txErr = tx.ExecContext(finishCtx, `UPDATE v3_evaluation_preparations SET state='failed',reason_code=$3,error_detail=$4,cost_json=$5,finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND owner=$2 AND state='preparing' AND preparation_attempt=$6`, p.ID, p.Owner, reason, detail, costRaw, p.PreparationAttempt)
	}
	if txErr != nil {
		s.setPreparationCoordinatorReason("preparation_result_store_unavailable", txErr)
		return
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		s.setPreparationCoordinatorReason("preparation_owner_changed", nil)
		return
	}
	cost["storage_seconds"] = time.Since(start).Seconds() - cost["total_seconds"].(float64)
	cost["total_seconds"] = time.Since(start).Seconds()
	costRaw, _ = json.Marshal(cost)
	if _, txErr = tx.ExecContext(finishCtx, "UPDATE v3_evaluation_preparations SET cost_json=$3 WHERE id=$1 AND owner=$2 AND state=$4", p.ID, p.Owner, costRaw, state); txErr != nil {
		s.setPreparationCoordinatorReason("preparation_result_store_unavailable", txErr)
		return
	}
	var finalSHA any
	if state == "ready" {
		finalSHA = digest
	}
	_, txErr = tx.ExecContext(finishCtx, `UPDATE v3_evaluation_preparation_attempts SET state=$4,reason_code=$5,document_sha256=$6,cost_json=$7,finished_at=clock_timestamp() WHERE preparation_id=$1 AND attempt=$2 AND owner=$3 AND state='preparing'`, p.ID, p.PreparationAttempt, p.Owner, state, reason, finalSHA, costRaw)
	if txErr == nil {
		txErr = tx.Commit()
	}
	if txErr != nil {
		s.setPreparationCoordinatorReason("preparation_result_store_unavailable", txErr)
	}
}

func preparationDocumentFits(existing, size, limit int64) bool {
	return (limit == evaluationProjectionLimit || limit == evaluationV2DocumentLimit) && existing >= 0 && existing <= preparationBudget && size > 0 && size <= limit && size <= preparationBudget-existing
}
