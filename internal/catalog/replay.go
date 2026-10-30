package catalog

import (
	"encoding/json"
	"github.com/TonyP4N/cpagx-go/internal/jobapi"
	"net/http"
	"net/http/httptest"
)

// Only verified terminal artifacts are visible. Running attempts continue to
// expose ordinary task status and cancellation, never unverified snapshot files.
func (s *Server) replayProjection(w http.ResponseWriter, r *http.Request, p *principal, dataset, id, kind string) {
	if compact, err := s.Internal.(*jobapi.Server).IsCompactRun(r, id); err == nil && compact {
		q := r.URL.Query()
		action := "metadata"
		switch kind {
		case "graph":
			action = "graph"
		case "evidence":
			action = "evidence"
		case "snapshots":
			action = "snapshot"
		case "revisions":
			action = "revisions"
		}
		if q.Has("revision") {
			q.Set("snapshot", q.Get("revision"))
			if kind == "result" {
				action = "snapshot"
			}
		}
		q.Set("action", action)
		r.URL.RawQuery = q.Encode()
		s.compactProjection(w, r, p, dataset, id)
		return
	}
	suffix := "replay-result"
	switch kind {
	case "revisions":
		suffix = "replay-revisions"
	case "snapshots":
		suffix = "replay-snapshot"
	case "evidence":
		suffix = "replay-evidence"
	case "graph":
		if r.URL.Query().Has("revision") {
			suffix = "replay-snapshot"
		} else {
			suffix = "replay-result"
		}
	}
	path := "/v1/jobs/" + id + "/" + suffix + "?" + r.URL.RawQuery
	req := httptest.NewRequest("GET", path, nil).WithContext(r.Context())
	req.Header.Set("Authorization", "Bearer "+s.cfg.WorkerToken)
	rec := httptest.NewRecorder()
	s.Internal.ServeHTTP(rec, req)
	if rec.Code != 200 {
		fail(w, 409, "result_unavailable", "verified replay result or revision unavailable or changed")
		return
	}
	var value any
	if json.Unmarshal(rec.Body.Bytes(), &value) != nil {
		fail(w, 409, "result_invalid", "verified replay projection invalid")
		return
	}
	if kind == "graph" {
		value = replayGraphProjection(value)
	}
	if s.audit(r.Context(), p, dataset, id, "replay_"+kind+"_read", "ok") != nil {
		fail(w, 503, "audit_unavailable", "replay read audit unavailable")
		return
	}
	respond(w, 200, value)
}

func replayGraphProjection(value any) map[string]any {
	envelope, _ := value.(map[string]any)
	version := envelope["replay_version"]
	snapshot := envelope
	if data, ok := snapshot["data"].(map[string]any); ok {
		snapshot = data
	}
	analysis, _ := snapshot["analysis"].(map[string]any)
	return map[string]any{"mode": "dual_source_replay", "replay_version": version, "revision_number": snapshot["revision_number"], "synthetic": analysis["synthetic"], "graph": snapshot["graph"]}
}
