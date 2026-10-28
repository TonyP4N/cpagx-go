// Package catalog is the opt-in v3 public catalog and authorization boundary.
package catalog

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TonyP4N/cpagx-go/internal/capacity"
	"github.com/TonyP4N/cpagx-go/internal/jobapi"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL            string `json:"database_url"`
	SharedRoot             string `json:"shared_root"`
	ControlRoot            string `json:"control_root"`
	PublicAddr             string `json:"public_addr"`
	InternalAddr           string `json:"internal_addr"`
	WorkerToken            string `json:"worker_token"`
	CoordinatorToken       string `json:"coordinator_token"`
	BootstrapAdminUsername string `json:"bootstrap_admin_username"`
	BootstrapAdminPassword string `json:"bootstrap_admin_password"`
	StaticRoot             string `json:"static_root"`
	PythonBin              string `json:"python_bin"`
	PythonPath             string `json:"python_path"`
	CapacityPolicy         string `json:"capacity_policy,omitempty"`
	ResourceProfile        string `json:"resource_profile,omitempty"`
}
type Server struct {
	DB       *sql.DB
	Root     string
	Internal http.Handler
	cfg      Config
	repo     jobs.Repository
}
type principal struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type auditWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *auditWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(b)
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)
var shaRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

func LoadConfig(path string) (Config, error) {
	var c Config
	st, e := os.Stat(path)
	if e != nil {
		return c, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return c, errors.New("v3 config must be a regular 0600 file")
	}
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("one config object required")
	}
	if c.CapacityPolicy != "" && c.CapacityPolicy != capacity.Engineering {
		return c, errors.New("unsupported site capacity policy")
	}
	if _, e = capacity.ArtifactBytes(c.ResourceProfile); e != nil {
		return c, e
	}
	if c.PublicAddr == "" {
		c.PublicAddr = "127.0.0.1:8095"
	}
	if c.InternalAddr == "" {
		c.InternalAddr = "127.0.0.1:8094"
	}
	if c.PythonBin == "" {
		c.PythonBin = "python3"
	}
	if c.DatabaseURL == "" || c.SharedRoot == "" || c.ControlRoot == "" || len(c.WorkerToken) < 24 || len(c.CoordinatorToken) < 24 || c.WorkerToken == c.CoordinatorToken {
		return c, errors.New("database, roots and distinct internal tokens are required")
	}
	if c.BootstrapAdminUsername == "" || c.BootstrapAdminPassword == "" {
		return c, errors.New("bootstrap administrator credentials required")
	}
	if !LoopbackAddr(c.PublicAddr) || !LoopbackAddr(c.InternalAddr) || c.PublicAddr == c.InternalAddr {
		return c, errors.New("public and internal listeners must be distinct loopback addresses")
	}
	return c, nil
}
func LoopbackAddr(addr string) bool {
	u, e := url.Parse("http://" + addr)
	if e != nil {
		return false
	}
	host := u.Hostname()
	return host == "127.0.0.1" || host == "[::1]" || host == "::1" || host == "localhost"
}
func New(db *sql.DB, c Config) (*Server, error) {
	if c.CapacityPolicy != "" && c.CapacityPolicy != capacity.Engineering {
		return nil, errors.New("unsupported site capacity policy")
	}
	if _, err := capacity.ArtifactBytes(c.ResourceProfile); err != nil {
		return nil, err
	}
	if c.CapacityPolicy != "" {
		if err := (jobs.Repository{DB: db}).EnableCapacityPolicy(context.Background(), c.CapacityPolicy); err != nil {
			return nil, err
		}
	}
	root, e := filepath.Abs(c.SharedRoot)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return nil, e
	}
	root, e = filepath.EvalSymlinks(root)
	if e != nil {
		return nil, e
	}
	control, e := filepath.Abs(c.ControlRoot)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(control, 0700); e != nil {
		return nil, e
	}
	control, e = filepath.EvalSymlinks(control)
	if e != nil {
		return nil, e
	}
	if contained(root, control) || contained(control, root) {
		return nil, errors.New("control root must be separate from shared root")
	}
	c.ControlRoot = control
	for _, sub := range []string{"inputs", "jobs", "inputs/catalog"} {
		p := filepath.Join(root, sub)
		if e = os.MkdirAll(p, 0700); e != nil {
			return nil, e
		}
		q, x := filepath.EvalSymlinks(p)
		if x != nil || q != p {
			return nil, errors.New("shared root directories cannot be symlinks")
		}
	}
	internal, e := jobapi.NewWithCoordinator(jobs.Repository{DB: db}, root, c.WorkerToken, c.CoordinatorToken, c.ControlRoot)
	if e != nil {
		return nil, e
	}
	internal.(*jobapi.Server).CapacityPolicy = c.CapacityPolicy
	internal.(*jobapi.Server).ResourceProfile = c.ResourceProfile
	internal.(*jobapi.Server).PythonBin = c.PythonBin
	internal.(*jobapi.Server).PythonPath = c.PythonPath
	s := &Server{DB: db, Root: root, Internal: internal, cfg: c, repo: jobs.Repository{DB: db}}
	if e = s.bootstrap(context.Background()); e != nil {
		return nil, e
	}
	return s, nil
}
func contained(parent, child string) bool {
	rel, e := filepath.Rel(parent, child)
	return e == nil && (rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."))
}
func (s *Server) bootstrap(ctx context.Context) error {
	var n int
	if e := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM v3_users").Scan(&n); e != nil {
		return e
	}
	if n != 0 {
		return nil
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(s.cfg.BootstrapAdminPassword), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	_, e = s.DB.ExecContext(ctx, "INSERT INTO v3_users(id,username,role,password_hash) VALUES($1,$2,'admin',$3) ON CONFLICT(username) DO NOTHING", newID(), s.cfg.BootstrapAdminUsername, string(hash))
	return e
}
func newID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code, msg string) {
	respond(w, status, map[string]any{"error": apiError{code, msg}})
}
func body(w http.ResponseWriter, r *http.Request, v any, max int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("one JSON object required")
	}
	return nil
}
func auditFields(p *principal, dataset, job string) (any, any, any) {
	var uid, ds, j any
	if p != nil {
		uid = p.ID
	}
	if dataset != "" {
		ds = dataset
	}
	if job != "" {
		j = job
	}
	return uid, ds, j
}
func auditTx(ctx context.Context, tx *sql.Tx, p *principal, dataset, job, action, outcome string) error {
	uid, ds, j := auditFields(p, dataset, job)
	_, e := tx.ExecContext(ctx, "INSERT INTO v3_audit_events(user_id,dataset_id,job_id,action,outcome) VALUES($1,$2,$3,$4,$5)", uid, ds, j, action, outcome)
	return e
}
func (s *Server) audit(ctx context.Context, p *principal, dataset, job, action, outcome string) error {
	uid, ds, j := auditFields(p, dataset, job)
	// Fixed fields only: no request bodies, cookies, passwords, paths, or worker credentials.
	_, e := s.DB.ExecContext(ctx, "INSERT INTO v3_audit_events(user_id,dataset_id,job_id,action,outcome) VALUES($1,$2,$3,$4,$5)", uid, ds, j, action, outcome)
	return e
}
func (s *Server) session(r *http.Request) (*principal, error) {
	cookie, e := r.Cookie("cpag_session")
	if e != nil {
		return nil, e
	}
	if len(cookie.Value) != 64 {
		return nil, errors.New("invalid session")
	}
	var p principal
	e = s.DB.QueryRowContext(r.Context(), `SELECT u.id,u.username,u.role FROM v3_sessions x JOIN v3_users u ON u.id=x.user_id WHERE x.token_hash=$1 AND x.revoked_at IS NULL AND x.expires_at>clock_timestamp() AND u.disabled_at IS NULL`, tokenHash(cookie.Value)).Scan(&p.ID, &p.Username, &p.Role)
	return &p, e
}
func (s *Server) can(ctx context.Context, p *principal, dataset string, write bool) bool {
	if p.Role == "admin" {
		return true
	}
	if write && p.Role == "viewer" {
		return false
	}
	var access string
	e := s.DB.QueryRowContext(ctx, "SELECT access FROM v3_dataset_acl WHERE dataset_id=$1 AND user_id=$2", dataset, p.ID).Scan(&access)
	if e != nil {
		return false
	}
	return !write || access == "analyst" || access == "owner"
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/v3/") && r.Method != "GET" && r.Method != "HEAD" {
		o := r.Header.Get("Origin")
		if (o != "" && o != "http://"+s.cfg.PublicAddr) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			fail(w, 403, "origin_denied", "request origin denied")
			return
		}
	}
	if r.URL.Path == "/health/live" {
		respond(w, 200, map[string]string{"status": "live"})
		return
	}
	if r.URL.Path == "/health/ready" {
		ctx, c := context.WithTimeout(r.Context(), 2*time.Second)
		defer c()
		if s.DB.PingContext(ctx) != nil {
			fail(w, 503, "not_ready", "database unavailable")
			return
		}
		respond(w, 200, map[string]string{"status": "ready"})
		return
	}
	if r.URL.Path == "/api/v3/session" {
		s.serveSession(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v3/") {
		p, e := s.session(r)
		if e != nil {
			fail(w, 401, "unauthenticated", "login required")
			return
		}
		tracked := &auditWriter{ResponseWriter: w}
		defer func() {
			if tracked.status >= 400 {
				_ = s.audit(r.Context(), p, "", "", "request_rejected", fmt.Sprintf("http_%d", tracked.status))
			}
		}()
		w = tracked
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v3/"), "/")
		switch parts[0] {
		case "users":
			s.serveUsers(w, r, p, parts)
		case "datasets":
			s.serveDatasets(w, r, p, parts)
		case "runs":
			s.serveRuns(w, r, p, parts)
		case "audit":
			s.serveAudit(w, r, p)
		default:
			fail(w, 404, "not_found", "route not found")
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/v1/") {
		fail(w, 404, "not_found", "route not found")
		return
	}
	if r.Method == "GET" && r.URL.Path == "/" && s.cfg.StaticRoot != "" {
		http.Redirect(w, r, "/workspace/", http.StatusFound)
		return
	}
	if r.Method == "GET" && s.cfg.StaticRoot != "" {
		s.serveStatic(w, r)
		return
	}
	fail(w, 404, "not_found", "route not found")
}
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(filepath.Clean("/"+r.URL.Path), "/")
	if rel == "" {
		rel = "index.html"
	}
	p := filepath.Join(s.cfg.StaticRoot, rel)
	if st, e := os.Stat(p); e == nil && st.IsDir() {
		p = filepath.Join(p, "index.html")
	}
	if st, e := os.Stat(p); e != nil || !st.Mode().IsRegular() {
		p = filepath.Join(s.cfg.StaticRoot, "index.html")
	}
	http.ServeFile(w, r, p)
}
func (s *Server) serveSession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		var q struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if body(w, r, &q, 4096) != nil {
			fail(w, 400, "invalid_request", "invalid login request")
			return
		}
		var p principal
		var hash string
		e := s.DB.QueryRowContext(r.Context(), "SELECT id,username,role,password_hash FROM v3_users WHERE username=$1 AND disabled_at IS NULL", q.Username).Scan(&p.ID, &p.Username, &p.Role, &hash)
		if e != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(q.Password)) != nil {
			s.audit(r.Context(), nil, "", "", "login", "denied")
			fail(w, 401, "invalid_credentials", "invalid credentials")
			return
		}
		raw := newID() + newID()
		tx, e := s.DB.BeginTx(r.Context(), nil)
		if e != nil {
			fail(w, 503, "database_error", "session unavailable")
			return
		}
		defer tx.Rollback()
		_, e = tx.ExecContext(r.Context(), "INSERT INTO v3_sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,clock_timestamp()+interval '12 hours')", newID(), p.ID, tokenHash(raw))
		if e == nil {
			e = auditTx(r.Context(), tx, &p, "", "", "login", "ok")
		}
		if e != nil || tx.Commit() != nil {
			fail(w, 503, "database_error", "session unavailable")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "cpag_session", Value: raw, Path: "/api/v3", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
		respond(w, 200, map[string]any{"user": p})
	case "GET":
		p, e := s.session(r)
		if e != nil {
			fail(w, 401, "unauthenticated", "login required")
			return
		}
		respond(w, 200, map[string]any{"user": p})
	case "DELETE":
		p, e := s.session(r)
		if e != nil {
			fail(w, 401, "unauthenticated", "login required")
			return
		}
		c, _ := r.Cookie("cpag_session")
		tx, e := s.DB.BeginTx(r.Context(), nil)
		if e != nil {
			fail(w, 503, "database_error", "session unavailable")
			return
		}
		defer tx.Rollback()
		_, e = tx.ExecContext(r.Context(), "UPDATE v3_sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1 AND revoked_at IS NULL", tokenHash(c.Value))
		if e == nil {
			e = auditTx(r.Context(), tx, p, "", "", "logout", "ok")
		}
		if e != nil || tx.Commit() != nil {
			fail(w, 503, "database_error", "session unavailable")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "cpag_session", Path: "/api/v3", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		respond(w, 200, map[string]bool{"ok": true})
	default:
		fail(w, 405, "method_not_allowed", "method not allowed")
	}
}
func (s *Server) serveUsers(w http.ResponseWriter, r *http.Request, p *principal, parts []string) {
	if len(parts) != 1 || p.Role != "admin" {
		fail(w, 403, "forbidden", "access denied")
		return
	}
	switch r.Method {
	case "GET":
		rows, e := s.DB.QueryContext(r.Context(), "SELECT id,username,role,disabled_at FROM v3_users ORDER BY username LIMIT 500")
		if e != nil {
			fail(w, 503, "database_error", "users unavailable")
			return
		}
		defer rows.Close()
		out := []any{}
		for rows.Next() {
			var id, n, role string
			var disabled *time.Time
			if rows.Scan(&id, &n, &role, &disabled) == nil {
				out = append(out, map[string]any{"id": id, "username": n, "role": role, "disabled_at": disabled})
			}
		}
		respond(w, 200, map[string]any{"users": out})
	case "POST":
		var q struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if body(w, r, &q, 4096) != nil || len(q.Username) < 2 || len(q.Username) > 100 || len(q.Password) < 12 || !(q.Role == "admin" || q.Role == "analyst" || q.Role == "viewer") {
			fail(w, 422, "invalid_user", "invalid user properties")
			return
		}
		h, e := bcrypt.GenerateFromPassword([]byte(q.Password), bcrypt.DefaultCost)
		if e != nil {
			fail(w, 500, "hash_error", "could not create user")
			return
		}
		id := newID()
		tx, e := s.DB.BeginTx(r.Context(), nil)
		if e != nil {
			fail(w, 503, "database_error", "user unavailable")
			return
		}
		defer tx.Rollback()
		_, e = tx.ExecContext(r.Context(), "INSERT INTO v3_users(id,username,role,password_hash) VALUES($1,$2,$3,$4)", id, q.Username, q.Role, string(h))
		if e == nil {
			e = auditTx(r.Context(), tx, p, "", "", "user_create", "ok")
		}
		if e != nil || tx.Commit() != nil {
			fail(w, 409, "user_conflict", "username exists")
			return
		}
		respond(w, 201, map[string]any{"user": principal{id, q.Username, q.Role}})
	default:
		fail(w, 405, "method_not_allowed", "method not allowed")
	}
}
func (s *Server) serveAudit(w http.ResponseWriter, r *http.Request, p *principal) {
	if p.Role != "admin" {
		fail(w, 403, "forbidden", "access denied")
		return
	}
	if r.Method != "GET" {
		fail(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	rows, e := s.DB.QueryContext(r.Context(), "SELECT id,occurred_at,user_id,dataset_id,job_id,action,outcome FROM v3_audit_events ORDER BY id DESC LIMIT 200")
	if e != nil {
		fail(w, 503, "database_error", "audit unavailable")
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id int64
		var at time.Time
		var uid, ds, job *string
		var action, outcome string
		if rows.Scan(&id, &at, &uid, &ds, &job, &action, &outcome) == nil {
			out = append(out, map[string]any{"id": id, "occurred_at": at, "user_id": uid, "dataset_id": ds, "job_id": job, "action": action, "outcome": outcome})
		}
	}
	respond(w, 200, map[string]any{"events": out})
}
func safeName(v string) bool {
	return v != "" && len(v) <= 200 && filepath.Base(v) == v && !strings.ContainsAny(v, "\\\x00/")
}
func errWrap(e error) string {
	if e == nil {
		return ""
	}
	return fmt.Sprint(e)
}
