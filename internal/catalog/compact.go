package catalog

import (
	"context"
	"encoding/json"
	"github.com/TonyP4N/cpagx-go/internal/jobapi"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"time"
)

// Dataset/run authorization is resolved by serveRuns before this route.
func (s *Server) compactProjection(w http.ResponseWriter, r *http.Request, p *principal, dataset, id string) {
	req := httptest.NewRequest("GET", "/v1/jobs/"+id+"/shared-query?"+r.URL.RawQuery, nil).WithContext(r.Context())
	req.Header.Set("Authorization", "Bearer "+s.cfg.WorkerToken)
	rec := httptest.NewRecorder()
	s.Internal.ServeHTTP(rec, req)
	if rec.Code != 200 {
		var detail struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &detail)
		switch detail.Code {
		case "verification_pending":
			fail(w, 409, "verification_pending", "complete source verification is pending")
		case "query_timeout":
			fail(w, 504, "query_timeout", "compact query exceeded its 10 second deadline")
		case "query_limit":
			fail(w, 422, "query_limit", "query exceeds the page, path or byte bounds; select a smaller page or narrower path")
		case "result_changed":
			fail(w, 409, "result_changed", "published bytes or run bindings changed")
		default:
			fail(w, 409, "result_unavailable", "verified compact result unavailable")
		}
		return
	}
	if s.audit(r.Context(), p, dataset, id, "compact_query", "ok") != nil {
		fail(w, 503, "audit_unavailable", "read audit unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(rec.Body.Bytes())
}

var compactDownloadSlot = make(chan struct{}, 1)

// The open descriptor is verified before streaming, avoiding a second path
// lookup between verification and download. Authentication remains in serveRuns.
func (s *Server) compactDownload(w http.ResponseWriter, r *http.Request, p *principal, dataset, id, name string) bool {
	internal := s.Internal.(*jobapi.Server)
	isCompact, err := internal.IsCompactRun(r, id)
	if err != nil || !isCompact {
		return false
	}
	select {
	case compactDownloadSlot <- struct{}{}:
		defer func() { <-compactDownloadSlot }()
	default:
		fail(w, 429, "download_busy", "another controlled download is in progress")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	controller := http.NewResponseController(w)
	if err = controller.SetWriteDeadline(time.Now().Add(120 * time.Second)); err != nil {
		fail(w, 503, "download_deadline_unavailable", "controlled download requires a bounded connection deadline")
		return true
	}
	defer controller.SetWriteDeadline(time.Time{})
	file, err := internal.OpenVerifiedCompactArtifact(r, id, name)
	if err != nil {
		fail(w, 409, "result_unavailable", "verified artifact unavailable or changed")
		return true
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		fail(w, 409, "result_unavailable", "artifact unavailable")
		return true
	}
	if s.audit(r.Context(), p, dataset, id, "artifact_download", "ok") != nil {
		fail(w, 503, "audit_unavailable", "download audit unavailable")
		return true
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(name)+"\"")
	http.ServeContent(w, r, filepath.Base(name), info.ModTime(), file)
	return true
}
