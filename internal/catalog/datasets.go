package catalog

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/TonyP4N/cpagx-go/internal/jobapi"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Server) serveDatasets(w http.ResponseWriter, r *http.Request, p *principal, parts []string) {
	if len(parts) == 1 {
		if r.Method == "POST" {
			s.createDataset(w, r, p)
		} else if r.Method == "GET" {
			s.listDatasets(w, r, p)
		} else {
			fail(w, 405, "method_not_allowed", "method not allowed")
		}
		return
	}
	id := parts[1]
	if !safeID.MatchString(id) {
		fail(w, 404, "not_found", "dataset not found")
		return
	}
	if !s.can(r.Context(), p, id, false) {
		fail(w, 404, "not_found", "dataset not found")
		return
	}
	if len(parts) == 2 && r.Method == "GET" {
		s.getDataset(w, r, p, id)
		return
	}
	if len(parts) < 3 {
		fail(w, 404, "not_found", "route not found")
		return
	}
	switch parts[2] {
	case "acl":
		if len(parts) == 3 && r.Method == "POST" {
			s.grantACL(w, r, p, id)
			return
		}
	case "files":
		if len(parts) == 3 {
			if r.Method == "GET" {
				s.listFiles(w, r, id)
			} else if r.Method == "POST" {
				s.uploadFile(w, r, p, id)
			} else {
				fail(w, 405, "method_not_allowed", "method not allowed")
			}
			return
		}
		if len(parts) == 5 && parts[4] == "download" && r.Method == "GET" {
			s.downloadFile(w, r, p, id, parts[3])
			return
		}
	case "configs":
		if len(parts) == 3 {
			if r.Method == "GET" {
				s.listConfigs(w, r, id)
			} else if r.Method == "POST" {
				s.createConfig(w, r, p, id)
			} else {
				fail(w, 405, "method_not_allowed", "method not allowed")
			}
			return
		}
		if len(parts) == 4 && r.Method == "GET" {
			s.getConfig(w, r, id, parts[3])
			return
		}
	case "preflight":
		if len(parts) == 3 && r.Method == "POST" {
			s.preflight(w, r, p, id)
			return
		}
	case "preflights":
		if len(parts) == 3 && r.Method == "GET" {
			s.listPreflights(w, r, id)
			return
		}
		if len(parts) == 4 && r.Method == "GET" {
			s.getPreflight(w, r, id, parts[3])
			return
		}
	}
	fail(w, 404, "not_found", "route not found")
}
func (s *Server) createDataset(w http.ResponseWriter, r *http.Request, p *principal) {
	if p.Role == "viewer" {
		fail(w, 403, "forbidden", "write access required")
		return
	}
	var q struct {
		Name             string `json:"name"`
		SourceKind       string `json:"source_kind"`
		Source           string `json:"source"`
		Batch            string `json:"batch"`
		AuthorizationRef string `json:"authorization_ref"`
	}
	if body(w, r, &q, 8192) != nil {
		fail(w, 400, "invalid_request", "invalid dataset request")
		return
	}
	if q.SourceKind != "synthetic" && q.SourceKind != "real" {
		fail(w, 400, "invalid_source_kind", "source_kind must be synthetic or real")
		return
	}
	if strings.TrimSpace(q.Name) == "" || len(q.Name) > 200 || len(q.Source) > 500 || len(q.Batch) > 200 || len(q.AuthorizationRef) > 500 {
		fail(w, 422, "invalid_dataset", "invalid dataset metadata")
		return
	}
	id := newID()
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_error", "dataset unavailable")
		return
	}
	defer tx.Rollback()
	_, e = tx.ExecContext(r.Context(), "INSERT INTO v3_datasets(id,name,source_kind,source,batch,authorization_ref,created_by) VALUES($1,$2,$3,$4,$5,$6,$7)", id, q.Name, q.SourceKind, q.Source, q.Batch, q.AuthorizationRef, p.ID)
	if e == nil {
		_, e = tx.ExecContext(r.Context(), "INSERT INTO v3_dataset_acl(dataset_id,user_id,access) VALUES($1,$2,'owner')", id, p.ID)
	}
	if e == nil {
		e = auditTx(r.Context(), tx, p, id, "", "dataset_create", "ok")
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 503, "database_error", "dataset unavailable")
		return
	}
	respond(w, 201, map[string]any{"dataset": map[string]any{"id": id, "name": q.Name, "source_kind": q.SourceKind, "verification_status": "accepted_unvalidated", "source": q.Source, "batch": q.Batch, "authorization_ref": q.AuthorizationRef, "access": "owner"}})
}
func (s *Server) listDatasets(w http.ResponseWriter, r *http.Request, p *principal) {
	rows, e := s.DB.QueryContext(r.Context(), `SELECT d.id,d.name,d.source_kind,d.verification_status,d.source,d.batch,d.authorization_ref,d.created_at,COALESCE(a.access,'admin') FROM v3_datasets d LEFT JOIN v3_dataset_acl a ON a.dataset_id=d.id AND a.user_id=$1 WHERE $2='admin' OR a.user_id IS NOT NULL ORDER BY d.created_at DESC LIMIT 500`, p.ID, p.Role)
	if e != nil {
		fail(w, 503, "database_error", "datasets unavailable")
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id, name, kind, status, source, batch, auth, access string
		var at time.Time
		if rows.Scan(&id, &name, &kind, &status, &source, &batch, &auth, &at, &access) == nil {
			out = append(out, map[string]any{"id": id, "name": name, "source_kind": kind, "verification_status": status, "source": source, "batch": batch, "authorization_ref": auth, "access": access, "created_at": at})
		}
	}
	respond(w, 200, map[string]any{"datasets": out})
}
func (s *Server) getDataset(w http.ResponseWriter, r *http.Request, p *principal, id string) {
	var name, kind, status, source, batch, auth string
	var at time.Time
	e := s.DB.QueryRowContext(r.Context(), "SELECT name,source_kind,verification_status,source,batch,authorization_ref,created_at FROM v3_datasets WHERE id=$1", id).Scan(&name, &kind, &status, &source, &batch, &auth, &at)
	if e != nil {
		fail(w, 404, "not_found", "dataset not found")
		return
	}
	access := "admin"
	if p.Role != "admin" {
		_ = s.DB.QueryRowContext(r.Context(), "SELECT access FROM v3_dataset_acl WHERE dataset_id=$1 AND user_id=$2", id, p.ID).Scan(&access)
	}
	files := s.files(r, id)
	configs := s.configs(r, id)
	respond(w, 200, map[string]any{"dataset": map[string]any{"id": id, "name": name, "source_kind": kind, "verification_status": status, "source": source, "batch": batch, "authorization_ref": auth, "access": access, "created_at": at}, "files": files, "configs": configs})
}
func (s *Server) grantACL(w http.ResponseWriter, r *http.Request, p *principal, id string) {
	if p.Role != "admin" {
		fail(w, 403, "forbidden", "admin required")
		return
	}
	var q struct {
		UserID string `json:"user_id"`
		Access string `json:"access"`
	}
	if body(w, r, &q, 4096) != nil || !safeID.MatchString(q.UserID) || (q.Access != "viewer" && q.Access != "analyst") {
		fail(w, 422, "invalid_acl", "invalid access grant")
		return
	}
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_error", "access unavailable")
		return
	}
	defer tx.Rollback()
	_, e = tx.ExecContext(r.Context(), "INSERT INTO v3_dataset_acl(dataset_id,user_id,access) VALUES($1,$2,$3) ON CONFLICT(dataset_id,user_id) DO UPDATE SET access=EXCLUDED.access WHERE v3_dataset_acl.access!='owner'", id, q.UserID, q.Access)
	if e == nil {
		e = auditTx(r.Context(), tx, p, id, "", "acl_grant", "ok")
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 409, "acl_conflict", "access grant failed")
		return
	}
	respond(w, 200, map[string]any{"dataset_id": id, "user_id": q.UserID, "access": q.Access})
}

type fileInfo struct {
	ID        string    `json:"id"`
	Role      string    `json:"role"`
	Filename  string    `json:"filename"`
	SHA       string    `json:"sha256"`
	Size      int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Server) files(r *http.Request, id string) []fileInfo {
	out := []fileInfo{}
	rows, e := s.DB.QueryContext(r.Context(), "SELECT f.id,f.role,f.filename,x.sha256,x.size_bytes,f.created_at FROM v3_dataset_files f JOIN v3_source_files x ON x.id=f.source_file_id WHERE f.dataset_id=$1 ORDER BY f.created_at", id)
	if e != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var item fileInfo
		if rows.Scan(&item.ID, &item.Role, &item.Filename, &item.SHA, &item.Size, &item.CreatedAt) == nil {
			out = append(out, item)
		}
	}
	return out
}
func (s *Server) listFiles(w http.ResponseWriter, r *http.Request, id string) {
	respond(w, 200, map[string]any{"files": s.files(r, id)})
}
func (s *Server) uploadFile(w http.ResponseWriter, r *http.Request, p *principal, id string) {
	if !s.can(r.Context(), p, id, true) {
		fail(w, 403, "forbidden", "write access required")
		return
	}
	role, name := r.URL.Query().Get("role"), r.URL.Query().Get("name")
	sha := r.Header.Get("X-Content-SHA256")
	key := r.Header.Get("Idempotency-Key")
	if !(role == "network" || role == "process") || !safeName(name) || !shaRE.MatchString(sha) || len(key) < 8 || len(key) > 160 || strings.ContainsAny(key, "\r\n") {
		fail(w, 422, "invalid_upload", "role, basename, hash and idempotency key required")
		return
	}
	ext := strings.ToLower(filepath.Ext(name))
	if (role == "network" && ext != ".pcap" && ext != ".pcapng") || (role == "process" && ext != ".csv" && ext != ".xls" && ext != ".xlsx") {
		fail(w, 422, "unsupported_format", "unsupported source file extension")
		return
	}
	limit := int64(64 << 20)
	if role == "process" {
		limit = 8 << 20
	}
	if r.ContentLength < 0 || r.ContentLength > limit {
		fail(w, 413, "size_limit", "known bounded content length required")
		return
	}
	dir := filepath.Join(s.Root, "inputs", "catalog", id)
	if e := os.MkdirAll(dir, 0700); e != nil {
		fail(w, 503, "storage_error", "storage unavailable")
		return
	}
	temp, e := os.CreateTemp(dir, ".upload-")
	if e != nil {
		fail(w, 503, "storage_error", "storage unavailable")
		return
	}
	defer os.Remove(temp.Name())
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(temp, h), http.MaxBytesReader(w, r.Body, limit+1))
	syncErr := temp.Sync()
	closeErr := temp.Close()
	if e != nil || syncErr != nil || closeErr != nil || n > limit || n != r.ContentLength {
		fail(w, 413, "size_limit", "upload interrupted or exceeds limit")
		return
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != sha {
		fail(w, 422, "checksum_mismatch", "uploaded bytes do not match declared SHA-256")
		return
	}
	var old fileInfo
	var oldKeyRole, oldName string
	e = s.DB.QueryRowContext(r.Context(), `SELECT f.id,f.role,f.filename,x.sha256,x.size_bytes,f.created_at FROM v3_dataset_files f JOIN v3_source_files x ON x.id=f.source_file_id WHERE f.dataset_id=$1 AND f.idempotency_key=$2`, id, key).Scan(&old.ID, &oldKeyRole, &oldName, &old.SHA, &old.Size, &old.CreatedAt)
	if e == nil {
		old.Role = oldKeyRole
		old.Filename = oldName
		if old.SHA == sha && old.Size == n && old.Role == role && old.Filename == name {
			respond(w, 200, map[string]any{"file": old})
			return
		}
		fail(w, 409, "idempotency_conflict", "key already used for different upload")
		return
	}
	if !errors.Is(e, sql.ErrNoRows) {
		fail(w, 503, "database_error", "file catalog unavailable")
		return
	}
	fileID, sourceID := newID(), newID()
	rel := filepath.Join("inputs", "catalog", id, fileID+ext)
	target := filepath.Join(s.Root, rel)
	if e = os.Rename(temp.Name(), target); e != nil {
		fail(w, 503, "storage_error", "storage unavailable")
		return
	}
	_ = os.Chmod(target, 0400)
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		os.Remove(target)
		fail(w, 503, "database_error", "file catalog unavailable")
		return
	}
	defer tx.Rollback()
	var locked string
	if tx.QueryRowContext(r.Context(), "SELECT id FROM v3_datasets WHERE id=$1 FOR UPDATE", id).Scan(&locked) != nil {
		os.Remove(target)
		fail(w, 404, "not_found", "dataset not found")
		return
	}
	_, e = tx.ExecContext(r.Context(), "INSERT INTO v3_source_files(id,sha256,size_bytes,storage_path) VALUES($1,$2,$3,$4)", sourceID, sha, n, rel)
	if e == nil {
		_, e = tx.ExecContext(r.Context(), "INSERT INTO v3_dataset_files(id,dataset_id,source_file_id,role,filename,idempotency_key,created_by) VALUES($1,$2,$3,$4,$5,$6,$7)", fileID, id, sourceID, role, name, key, p.ID)
	}
	if e == nil {
		e = auditTx(r.Context(), tx, p, id, "", "file_upload", "ok")
	}
	if e != nil || tx.Commit() != nil {
		os.Remove(target)
		fail(w, 409, "upload_conflict", "upload catalog conflict")
		return
	}
	respond(w, 201, map[string]any{"file": fileInfo{fileID, role, name, sha, n, time.Now().UTC()}})
}
func (s *Server) downloadFile(w http.ResponseWriter, r *http.Request, p *principal, dataset, fileID string) {
	if !safeID.MatchString(fileID) {
		fail(w, 404, "not_found", "file not found")
		return
	}
	var rel, sha, name string
	var size int64
	e := s.DB.QueryRowContext(r.Context(), `SELECT x.storage_path,x.sha256,f.filename,x.size_bytes FROM v3_dataset_files f JOIN v3_source_files x ON x.id=f.source_file_id WHERE f.dataset_id=$1 AND f.id=$2`, dataset, fileID).Scan(&rel, &sha, &name, &size)
	if e != nil {
		fail(w, 404, "not_found", "file not found")
		return
	}
	path, e := s.verifiedFile(rel, sha, size)
	if e != nil {
		fail(w, 409, "file_changed", "stored source changed")
		return
	}
	if s.audit(r.Context(), p, dataset, "", "file_download", "ok") != nil {
		fail(w, 503, "audit_unavailable", "download audit unavailable")
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	http.ServeFile(w, r, path)
}
func (s *Server) verifiedFile(rel, sha string, size int64) (string, error) {
	if filepath.IsAbs(rel) || filepath.Clean(rel) != rel || !strings.HasPrefix(rel, "inputs/catalog/") || strings.Contains(rel, "..") || !shaRE.MatchString(sha) {
		return "", errors.New("unsafe file reference")
	}
	p := filepath.Join(s.Root, rel)
	real, e := filepath.EvalSymlinks(p)
	if e != nil || real != p {
		return "", errors.New("symlink or missing file")
	}
	f, e := os.Open(p)
	if e != nil {
		return "", e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() != size {
		return "", errors.New("source size changed")
	}
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	if hex.EncodeToString(h.Sum(nil)) != sha {
		return "", errors.New("source hash changed")
	}
	return p, nil
}

type configInfo struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Version     int       `json:"version"`
	ProfileSHA  string    `json:"profile_sha256"`
	Fingerprint string    `json:"config_fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Server) configs(r *http.Request, id string) []configInfo {
	out := []configInfo{}
	rows, e := s.DB.QueryContext(r.Context(), "SELECT id,kind,version,profile_sha256,config_fingerprint,created_at FROM v3_config_versions WHERE dataset_id=$1 ORDER BY kind,version", id)
	if e != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var c configInfo
		if rows.Scan(&c.ID, &c.Kind, &c.Version, &c.ProfileSHA, &c.Fingerprint, &c.CreatedAt) == nil {
			out = append(out, c)
		}
	}
	return out
}
func (s *Server) listConfigs(w http.ResponseWriter, r *http.Request, id string) {
	respond(w, 200, map[string]any{"configs": s.configs(r, id)})
}
func (s *Server) getConfig(w http.ResponseWriter, r *http.Request, dataset, id string) {
	if !safeID.MatchString(id) {
		fail(w, 404, "not_found", "config not found")
		return
	}
	var c configInfo
	var raw json.RawMessage
	e := s.DB.QueryRowContext(r.Context(), "SELECT id,kind,version,profile_sha256,config_fingerprint,created_at,profile_json FROM v3_config_versions WHERE dataset_id=$1 AND id=$2", dataset, id).Scan(&c.ID, &c.Kind, &c.Version, &c.ProfileSHA, &c.Fingerprint, &c.CreatedAt, &raw)
	if e != nil {
		fail(w, 404, "not_found", "config not found")
		return
	}
	respond(w, 200, map[string]any{"config": c, "document": raw})
}
func (s *Server) createConfig(w http.ResponseWriter, r *http.Request, p *principal, id string) {
	if !s.can(r.Context(), p, id, true) {
		fail(w, 403, "forbidden", "write access required")
		return
	}
	var q struct {
		Kind     string          `json:"kind"`
		Document json.RawMessage `json:"document"`
	}
	if body(w, r, &q, 65536) != nil || (q.Kind != "intake" && q.Kind != "dual") || len(q.Document) == 0 {
		fail(w, 422, "invalid_config", "kind and document required")
		return
	}
	var doc map[string]any
	if validateUniqueJSON(q.Document) != nil || json.Unmarshal(q.Document, &doc) != nil || doc == nil {
		fail(w, 422, "invalid_config", "document object required")
		return
	}
	var sourceKind string
	if s.DB.QueryRowContext(r.Context(), "SELECT source_kind FROM v3_datasets WHERE id=$1", id).Scan(&sourceKind) != nil {
		fail(w, 404, "not_found", "dataset not found")
		return
	}
	if q.Kind == "dual" && (doc["synthetic"] != (sourceKind == "synthetic") || (sourceKind == "real" && doc["analysis_mode"] != "bounded-real-capable-v1")) {
		fail(w, 422, "unsupported_source", "dual profile source category must match dataset and explicit bounded mode is required for real input")
		return
	}
	fingerprint, e := jobapi.DualProfileFingerprint(q.Document)
	if e != nil {
		fail(w, 422, "invalid_config", "invalid canonical profile")
		return
	}
	sum := sha256.Sum256(q.Document)
	sha := hex.EncodeToString(sum[:])
	cfgID := newID()
	// The row lock serializes version allocation for each dataset, including both kinds.
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_error", "config unavailable")
		return
	}
	defer tx.Rollback()
	var locked string
	if tx.QueryRowContext(r.Context(), "SELECT id FROM v3_datasets WHERE id=$1 FOR UPDATE", id).Scan(&locked) != nil {
		fail(w, 404, "not_found", "dataset not found")
		return
	}
	var version int
	e = tx.QueryRowContext(r.Context(), "SELECT coalesce(max(version),0)+1 FROM v3_config_versions WHERE dataset_id=$1 AND kind=$2", id, q.Kind).Scan(&version)
	if e != nil {
		fail(w, 503, "database_error", "config unavailable")
		return
	}
	dir := filepath.Join(s.Root, "inputs", "catalog", id, "profiles")
	if e = os.MkdirAll(dir, 0700); e != nil {
		fail(w, 503, "storage_error", "storage unavailable")
		return
	}
	rel := filepath.Join("inputs", "catalog", id, "profiles", cfgID+".json")
	path := filepath.Join(s.Root, rel)
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if e != nil {
		fail(w, 503, "storage_error", "config unavailable")
		return
	}
	_, e = f.Write(q.Document)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		os.Remove(path)
		fail(w, 503, "storage_error", "config unavailable")
		return
	}
	_, e = tx.ExecContext(r.Context(), "INSERT INTO v3_config_versions(id,dataset_id,kind,version,profile_storage_path,profile_sha256,config_fingerprint,profile_json,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", cfgID, id, q.Kind, version, rel, sha, fingerprint, string(q.Document), p.ID)
	if e == nil {
		e = auditTx(r.Context(), tx, p, id, "", "config_create", "ok")
	}
	if e != nil || tx.Commit() != nil {
		os.Remove(path)
		fail(w, 503, "database_error", "config unavailable")
		return
	}
	respond(w, 201, map[string]any{"config": configInfo{cfgID, q.Kind, version, sha, fingerprint, time.Now().UTC()}})
}
