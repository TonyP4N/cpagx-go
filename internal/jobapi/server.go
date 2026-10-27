// Package jobapi exposes only the opt-in M4 queue; it is never mounted by the default server.
package jobapi

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TonyP4N/cpagx-go/internal/contracts"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Ref struct {
	Path string `json:"path"`
	SHA  string `json:"sha256"`
}
type Payload struct {
	Kind        string `json:"kind,omitempty"`
	Network     Ref    `json:"network"`
	Networks    []Ref  `json:"networks,omitempty"`
	Process     Ref    `json:"process"`
	Profile     Ref    `json:"profile"`
	Fingerprint string `json:"config_fingerprint"`
}
type Server struct {
	Repo                           jobs.Repository
	Root, Secret                   string
	CoordinatorSecret, ControlRoot string
}

var identity = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)
var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func New(repo jobs.Repository, root, secret string) (http.Handler, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("shared root is required")
	}
	if len(secret) < 24 {
		return nil, errors.New("internal secret must contain at least 24 characters")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"inputs", "jobs"} {
		p := filepath.Join(real, name)
		if err = os.Mkdir(p, 0700); err != nil && !os.IsExist(err) {
			return nil, err
		}
		resolved, e := filepath.EvalSymlinks(p)
		if e != nil || resolved != p {
			return nil, errors.New("shared directories must not be symlinks")
		}
	}
	return &Server{Repo: repo, Root: real, Secret: secret, ControlRoot: real}, nil
}

// Coordinator credentials are separate from claim/heartbeat credentials and never
// enter the computation container. Control root must remain host-only.
func NewWithCoordinator(repo jobs.Repository, root, secret, coordinator, controlRoot string) (http.Handler, error) {
	h, err := New(repo, root, secret)
	if err != nil {
		return nil, err
	}
	server := h.(*Server)
	if coordinator != "" {
		if len(coordinator) < 24 || coordinator == secret {
			return nil, errors.New("distinct coordinator secret of at least 24 characters required")
		}
		server.CoordinatorSecret = coordinator
	}
	if controlRoot != "" {
		server.ControlRoot, err = filepath.Abs(controlRoot)
		if err != nil {
			return nil, err
		}
	}
	return server, nil
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("one JSON object required")
	}
	return nil
}
func (s *Server) file(rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, "\\") || filepath.Clean(rel) != rel || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", errors.New("invalid relative path")
	}
	p := filepath.Join(s.Root, rel)
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	if real != p {
		return "", errors.New("symlinks forbidden")
	}
	return p, nil
}
func (s *Server) check(ref Ref) (int64, error) {
	if !shaPattern.MatchString(ref.SHA) {
		return 0, errors.New("invalid sha256")
	}
	p, err := s.file(ref.Path)
	if err != nil {
		return 0, err
	}
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 0, errors.New("regular file required")
	}
	if info.Size() > 64<<20 {
		return 0, errors.New("file exceeds 64MiB")
	}
	if strings.HasSuffix(ref.Path, "manifest.json") && info.Size() > 65536 {
		return 0, errors.New("manifest exceeds 64KiB")
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, err
	}
	if hex.EncodeToString(h.Sum(nil)) != ref.SHA {
		return 0, errors.New("file digest mismatch")
	}
	return n, nil
}
func (s *Server) validPayload(p Payload) error {
	if p.Kind != "" && p.Kind != "packet" && p.Kind != "dual-source" {
		return errors.New("unsupported payload kind")
	}
	if !shaPattern.MatchString(p.Fingerprint) {
		return errors.New("invalid config fingerprint")
	}
	pth, err := s.file(p.Profile.Path)
	if err != nil {
		return err
	}
	info, err := os.Stat(pth)
	if err != nil {
		return err
	}
	if info.Size() > 16<<20 {
		return errors.New("profile exceeds 16MiB")
	}
	raw, err := os.ReadFile(pth)
	if err != nil {
		return err
	}
	var config any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err = dec.Decode(&config); err != nil {
		return err
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("invalid profile")
	}
	var numericCheck func(any) error
	numericCheck = func(v any) error {
		switch x := v.(type) {
		case string:
			if p.Kind != "dual-source" && strings.ContainsAny(x, "\u2028\u2029") {
				return errors.New("M4 profile excludes Unicode line separators")
			}
		case json.Number:
			if p.Kind != "dual-source" && (string(x) == "-0" || strings.ContainsAny(string(x), ".eE")) {
				return errors.New("M4 profile numbers must be integers")
			}
		case map[string]any:
			for key, v := range x {
				if err := numericCheck(key); err != nil {
					return err
				}
				if err := numericCheck(v); err != nil {
					return err
				}
			}
		case []any:
			for _, v := range x {
				if err := numericCheck(v); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if p.Kind == "packet" {
		obj, ok := config.(map[string]any)
		if !ok || obj["synthetic"] != true || obj["adapter"] != "synthetic-packet-1" {
			return errors.New("invalid packet profile")
		}
	}
	if p.Kind == "dual-source" {
		if err := contracts.Validate(dualSchemaDir(), "DualSourceProfile", raw); err != nil {
			return err
		}
		doc, _ := config.(map[string]any)
		if (doc["synthetic"] == false || doc["analysis_mode"] == "bounded-real-capable-v1") && !ReadyRealDualBasis(doc) {
			return errors.New("real input requires documented provenance/mapping/time basis")
		}
		if len(p.Networks) > 0 && doc["analysis_mode"] != "bounded-real-capable-v1" {
			return errors.New("multiple captures require explicit bounded mode")
		}
		if err := validateDualProfile(config); err != nil {
			return err
		}
	}
	if err = numericCheck(config); err != nil {
		return err
	}
	canon, err := pythonCanonical(config)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canon)
	if hex.EncodeToString(sum[:]) != p.Fingerprint {
		return errors.New("profile config fingerprint mismatch")
	}
	refs, err := p.networkRefs()
	if err != nil {
		return err
	}
	var networkBytes int64
	for _, ref := range refs {
		n, e := s.check(ref)
		if e != nil {
			return e
		}
		networkBytes += n
	}
	if networkBytes > 16<<20 {
		return errors.New("capture aggregate exceeds 16MiB analysis bound")
	}
	for _, ref := range append(refs, p.Process, p.Profile) {
		if !strings.HasPrefix(ref.Path, "inputs/") {
			return errors.New("inputs must be under inputs/")
		}
		if n, err := s.check(ref); err != nil {
			return err
		} else if p.Kind == "dual-source" && ((ref.Path == p.Process.Path && n > 2<<20) || (ref.Path == p.Profile.Path && n > 65536)) {
			return errors.New("dual-source input exceeds service limit")
		} else if n > 16<<20 {
			return errors.New("input exceeds 16MiB")
		}
	}
	return nil
}

// ValidatePayload reuses the M4 source, profile and fingerprint checks at the
// public catalog boundary before its transaction inserts an M4 job.
func (s *Server) ValidatePayload(p Payload) error { return s.validPayload(p) }
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	coordinatorOp := r.URL.Path == "/v1/executions" || strings.HasSuffix(r.URL.Path, "/execution") || strings.HasSuffix(r.URL.Path, "/exit") || strings.HasSuffix(r.URL.Path, "/attempts") || strings.HasSuffix(r.URL.Path, "/not-started")
	expected := s.Secret
	if coordinatorOp {
		expected = s.CoordinatorSecret
	}
	credential := []byte(r.Header.Get("Authorization"))
	dualRead := strings.HasSuffix(r.URL.Path, "/dual-result") || strings.HasSuffix(r.URL.Path, "/dual-evidence")
	authenticated := expected != "" && subtle.ConstantTimeCompare(credential, []byte("Bearer "+expected)) == 1
	if dualRead && s.CoordinatorSecret != "" {
		authenticated = authenticated || subtle.ConstantTimeCompare(credential, []byte("Bearer "+s.CoordinatorSecret)) == 1
	}
	if !authenticated {
		reply(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	fail := func(err error) {
		status := 400
		if errors.Is(err, jobs.ErrStale) {
			status = 409
		}
		if errors.Is(err, sql.ErrNoRows) {
			status = 404
		}
		reply(w, status, map[string]string{"error": err.Error()})
	}
	if r.URL.Path == "/v1/executions" && r.Method == "GET" {
		items, err := s.Repo.DiscoverExecutions(r.Context(), r.URL.Query().Get("location"))
		if err != nil {
			fail(err)
			return
		}
		reply(w, 200, items)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if r.URL.Path == "/v1/jobs" && r.Method == "POST" {
		var q struct {
			ID      string  `json:"id"`
			Max     int     `json:"max_attempts"`
			Payload Payload `json:"payload"`
		}
		if err := decode(w, r, &q); err != nil {
			fail(err)
			return
		}
		if !identity.MatchString(q.ID) {
			fail(errors.New("invalid id"))
			return
		}
		if err := s.validPayload(q.Payload); err != nil {
			fail(err)
			return
		}
		refs := []*Ref{&q.Payload.Network}
		if len(q.Payload.Networks) > 0 {
			refs = nil
			for i := range q.Payload.Networks {
				refs = append(refs, &q.Payload.Networks[i])
			}
		}
		refs = append(refs, &q.Payload.Process, &q.Payload.Profile)
		for index, ref := range refs {
			source, e := s.file(ref.Path)
			if e != nil {
				fail(e)
				return
			}
			destination := filepath.Join("inputs", fmt.Sprintf("%s-%d-%s%s", q.ID, index, ref.SHA, filepath.Ext(ref.Path)))
			target := filepath.Join(s.Root, destination)
			in, e := os.Open(source)
			if e != nil {
				fail(e)
				return
			}
			out, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
			if e == nil {
				_, e = io.Copy(out, in)
				if e == nil {
					e = out.Sync()
				}
				ce := out.Close()
				if e == nil {
					e = ce
				}
			}
			in.Close()
			if e != nil {
				fail(e)
				return
			}
			ref.Path = destination
			if _, e = s.check(*ref); e != nil {
				fail(e)
				return
			}
		}
		if len(q.Payload.Networks) > 0 {
			q.Payload.Network = q.Payload.Networks[0]
		}
		b, _ := json.Marshal(q.Payload)
		if err := s.Repo.EnqueuePayload(r.Context(), q.ID, q.Max, b); err != nil {
			fail(err)
			return
		}
		reply(w, 201, map[string]string{"id": q.ID})
		return
	}
	if r.URL.Path == "/v1/claim" && r.Method == "POST" {
		var q struct {
			Worker   string `json:"worker"`
			Lease    int    `json:"lease_seconds"`
			Executor string `json:"executor"`
			Location string `json:"location"`
		}
		if err := decode(w, r, &q); err != nil {
			fail(err)
			return
		}
		if !identity.MatchString(q.Worker) {
			fail(errors.New("invalid worker"))
			return
		}
		var c jobs.Claim
		var err error
		if q.Executor == "" && q.Location == "" {
			c, err = s.Repo.Claim(r.Context(), q.Worker, time.Duration(q.Lease)*time.Second)
		} else {
			c, err = s.Repo.ClaimExecution(r.Context(), q.Worker, time.Duration(q.Lease)*time.Second, q.Executor, q.Location)
		}
		if err == sql.ErrNoRows {
			w.WriteHeader(204)
			return
		}
		if err != nil {
			fail(err)
			return
		}
		st, err := s.Repo.Status(r.Context(), c.ID)
		if err != nil {
			fail(err)
			return
		}
		out := fmt.Sprintf("jobs/%s/attempt-%d", c.ID, c.Attempt)
		if err = os.MkdirAll(filepath.Join(s.Root, "jobs", c.ID), 0700); err == nil {
			_, err = s.file(filepath.Join("jobs", c.ID))
		}
		if err != nil {
			s.Repo.Fail(r.Context(), c, "attempt directory unavailable", false)
			fail(err)
			return
		}
		reply(w, 200, map[string]any{"id": c.ID, "attempt": c.Attempt, "worker": c.Worker, "token": c.Token, "payload": st.Payload, "output_dir": out, "lease_seconds": q.Lease, "executor": q.Executor, "location": q.Location})
		return
	}
	if len(parts) < 3 || parts[0] != "v1" || parts[1] != "jobs" || !identity.MatchString(parts[2]) {
		http.NotFound(w, r)
		return
	}
	id := parts[2]
	if len(parts) == 3 && r.Method == "GET" {
		st, err := s.Repo.Status(r.Context(), id)
		if err != nil {
			fail(err)
			return
		}
		reply(w, 200, st)
		return
	}
	if len(parts) == 4 && r.Method == "GET" && (parts[3] == "dual-result" || parts[3] == "dual-evidence") {
		if err := s.serveDual(w, r, id, parts[3]); err != nil {
			reply(w, 409, map[string]string{"error": err.Error()})
		}
		return
	}
	if len(parts) == 4 && parts[3] == "attempts" && r.Method == "GET" {
		rows, err := s.Repo.DB.QueryContext(r.Context(), `SELECT attempt,worker,attempt_token,location,container_id,exited_at,executor_kind,start_revoked_at FROM m4_job_attempts WHERE job_id=$1 ORDER BY attempt`, id)
		if err != nil {
			fail(err)
			return
		}
		defer rows.Close()
		result := []map[string]any{}
		for rows.Next() {
			var attempt int
			var worker, token, location, containerID, executor string
			var revoked *time.Time
			var exited *time.Time
			if err = rows.Scan(&attempt, &worker, &token, &location, &containerID, &exited, &executor, &revoked); err != nil {
				fail(err)
				return
			}
			result = append(result, map[string]any{"id": id, "attempt": attempt, "worker": worker, "token": token, "location": location, "container_id": containerID, "exited_at": exited, "executor": executor, "start_revoked_at": revoked})
		}
		if err = rows.Err(); err != nil {
			fail(err)
			return
		}
		reply(w, 200, result)
		return
	}
	if len(parts) != 4 || r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	op := parts[3]
	if op == "cancel" {
		if err := s.Repo.Cancel(r.Context(), id); err != nil {
			fail(err)
			return
		}
		st, err := s.Repo.Status(r.Context(), id)
		if err != nil {
			fail(err)
			return
		}
		reply(w, 200, map[string]string{"state": st.State})
		return
	}
	var q struct {
		Attempt     int               `json:"attempt"`
		Worker      string            `json:"worker"`
		Token       string            `json:"token"`
		Lease       int               `json:"lease_seconds"`
		Message     string            `json:"message"`
		Retryable   bool              `json:"retryable"`
		ManifestSHA string            `json:"manifest_sha256"`
		Location    string            `json:"location"`
		ContainerID string            `json:"container_id"`
		Scope       string            `json:"scope"`
		Removed     bool              `json:"removed"`
		Exited      bool              `json:"exited"`
		InspectedID string            `json:"inspected_id"`
		Running     *bool             `json:"running"`
		PID         *int              `json:"pid"`
		Labels      map[string]string `json:"labels"`
	}
	if err := decode(w, r, &q); err != nil {
		fail(err)
		return
	}
	c := jobs.Claim{ID: id, Attempt: q.Attempt, Worker: q.Worker, Token: q.Token}
	var err error
	switch op {
	case "not-started":
		err = s.Repo.RevokeUnstarted(r.Context(), c, q.Location)
	case "execution":
		err = s.Repo.RegisterExecution(r.Context(), c, q.Location, q.ContainerID)
	case "exit":
		err = s.Repo.RecordExit(r.Context(), c, jobs.ExitProof{ID: id, Attempt: c.Attempt, Worker: c.Worker, Token: c.Token, Location: q.Location, ContainerID: q.ContainerID, Scope: q.Scope, Exited: q.Exited, Removed: q.Removed, InspectedID: q.InspectedID, Running: q.Running, PID: q.PID, Labels: q.Labels})
	case "heartbeat":
		err = s.Repo.Heartbeat(r.Context(), c, time.Duration(q.Lease)*time.Second)
	case "fail":
		err = s.Repo.Fail(r.Context(), c, q.Message, q.Retryable)
	case "ack-cancel":
		err = s.Repo.RefreshExitEvidence(r.Context(), s.ControlRoot, c.ID)
		if err == nil {
			err = s.Repo.AcknowledgeCancel(r.Context(), c)
		}
	case "complete":
		err = s.complete(r, c, q.ManifestSHA)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		if errors.Is(err, jobs.ErrStale) {
			st, _ := s.Repo.Status(r.Context(), id)
			reply(w, 409, map[string]string{"error": err.Error(), "state": st.State})
			return
		}
		fail(err)
		return
	}
	reply(w, 200, map[string]string{"ok": "true"})
}

type Manifest struct {
	Fingerprint string            `json:"config_fingerprint"`
	Inputs      map[string]string `json:"inputs"`
	Networks    []string          `json:"networks,omitempty"`
	Artifacts   []struct {
		Path string `json:"path"`
		SHA  string `json:"sha256"`
		Size int64  `json:"size"`
	} `json:"artifacts"`
}

func (s *Server) complete(r *http.Request, c jobs.Claim, sha string) error {
	done, e := s.Repo.IsCompleted(r.Context(), c, sha)
	if e != nil {
		return e
	}

	st, err := s.Repo.Status(r.Context(), c.ID)
	if err != nil {
		return err
	}
	var p Payload
	if err = json.Unmarshal(st.Payload, &p); err != nil {
		return err
	}
	if err = s.validPayload(p); err != nil {
		return err
	}
	if !done {
		if err = s.Repo.CheckPublication(r.Context(), c); err != nil {
			return err
		}
	}
	base := fmt.Sprintf("jobs/%s/attempt-%d/", c.ID, c.Attempt)
	if _, err = s.check(Ref{base + "manifest.json", sha}); err != nil {
		return err
	}
	path, err := s.file(base + "manifest.json")
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var m Manifest
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if err = d.Decode(&m); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid manifest")
	}
	if m.Fingerprint != p.Fingerprint || !publicationInputsMatch(p, m.Inputs, m.Networks) || len(m.Artifacts) == 0 || len(m.Artifacts) > 100 {
		return errors.New("manifest input mismatch or artifact count")
	}
	seen := map[string]bool{}
	for _, a := range m.Artifacts {
		if seen[a.Path] || a.Path == "manifest.json" || !validArtifactPath(a.Path, p.Kind) {
			return errors.New("invalid artifact name")
		}
		seen[a.Path] = true
		n, e := s.check(Ref{base + a.Path, a.SHA})
		if e != nil {
			return e
		}
		if n != a.Size {
			return errors.New("artifact size mismatch")
		}
	}
	required := []string{"dataset.json", "events.json", "graph.json", "quality.json", "run_manifest.json"}
	if p.Kind == "packet" {
		required = append(required, "packet_observations.json")
	} else if p.Kind == "dual-source" {
		required = dualArtifactNamesFor(p)
	}
	if len(m.Artifacts) != len(required) {
		return errors.New("wrapper artifact set mismatch")
	}
	for _, name := range required {
		if !seen[name] {
			return errors.New("missing required core artifact")
		}
	}
	corePath, err := s.file(base + "run_manifest.json")
	if err != nil {
		return err
	}
	coreRaw, err := os.ReadFile(corePath)
	if err != nil {
		return err
	}
	var core struct {
		Schema    string `json:"schema_version"`
		Mode      string `json:"mode"`
		Config    string `json:"config_fingerprint"`
		Input     string `json:"input_fingerprint"`
		Synthetic bool   `json:"synthetic"`
		Status    string `json:"status"`
		Artifacts []struct {
			Path string `json:"path"`
			SHA  string `json:"sha256"`
			Size int64  `json:"size_bytes"`
		} `json:"artifacts"`
	}
	if err = json.Unmarshal(coreRaw, &core); err != nil {
		return err
	}
	inputValues := []map[string]any{}
	networkRefs, _ := p.networkRefs()
	for i, ref := range append(networkRefs, p.Process) {
		n, e := s.check(ref)
		if e != nil {
			return e
		}
		kind := "network"
		if i == len(networkRefs) {
			kind = "process"
		}
		inputValues = append(inputValues, map[string]any{"kind": kind, "sha256": ref.SHA, "size_bytes": n})
	}
	inputBytes, _ := json.Marshal(inputValues)
	inputSum := sha256.Sum256(inputBytes)
	if core.Input != hex.EncodeToString(inputSum[:]) {
		return errors.New("core input fingerprint mismatch")
	}
	if core.Schema != "1.0.0" || core.Mode != "offline" || core.Config != p.Fingerprint || (p.Kind != "dual-source" && !core.Synthetic) || (core.Status != "succeeded" && core.Status != "succeeded_with_warnings") || len(core.Artifacts) != len(required)-1 {
		return errors.New("invalid core manifest")
	}
	coreSeen := map[string]bool{}
	for _, a := range core.Artifacts {
		if coreSeen[a.Path] || !(map[string]bool{"dataset.json": true, "events.json": true, "graph.json": true, "quality.json": true}[a.Path] || (p.Kind == "packet" && a.Path == "packet_observations.json") || (p.Kind == "dual-source" && validArtifactPath(a.Path, p.Kind) && a.Path != "run_manifest.json")) {
			return errors.New("invalid core artifact set")
		}
		coreSeen[a.Path] = true
		matched := false
		for _, w := range m.Artifacts {
			if a.Path == w.Path && a.SHA == w.SHA && a.Size == w.Size {
				matched = true
			}
		}
		if !matched {
			return errors.New("core artifact mismatch")
		}
	}
	if p.Kind == "packet" {
		if err = s.validatePacket(base, p); err != nil {
			return err
		}
	}
	if p.Kind == "dual-source" {
		if err = s.validateDual(base, p, m, coreRaw); err != nil {
			return err
		}
	}
	key, err := jobs.ArtifactKey(c, sha)
	if err != nil {
		return err
	} // Publish a content-addressed manifest with exclusive creation.
	if done {
		_, e := s.check(Ref{key, sha})
		return e
	}
	dst := filepath.Join(s.Root, key)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	copiedDigest := sha256.Sum256(data)
	if hex.EncodeToString(copiedDigest[:]) != sha {
		return errors.New("manifest changed during publication")
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if os.IsExist(err) {
		if _, e := s.check(Ref{key, sha}); e != nil {
			return e
		}
		return s.Repo.Complete(r.Context(), c, key, sha)
	}
	if err != nil {
		return err
	}
	_, err = out.Write(data)
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return s.Repo.Complete(r.Context(), c, key, sha)
}
