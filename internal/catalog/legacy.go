package catalog

import (
	"context"
	"net/http"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/jobapi"
)

func (s *Server) legacyRead(w http.ResponseWriter, r *http.Request, p *principal, parts []string) {
	if p.Role != "admin" {
		fail(w, 403, "forbidden", "historical jobs without dataset ACLs require an administrator")
		return
	}
	if r.Method != "GET" {
		fail(w, 405, "history_read_only", "this entry is read-only")
		return
	}
	list := len(parts) == 4
	if (!list && (len(parts) != 6 || parts[5] != "download")) || parts[1] != "jobs" || !safeID.MatchString(parts[2]) || parts[3] != "artifacts" {
		fail(w, 404, "not_found", "historical route unavailable")
		return
	}
	id := parts[2]
	select {
	case compactDownloadSlot <- struct{}{}:
		defer func() { <-compactDownloadSlot }()
	default:
		fail(w, 429, "download_busy", "another controlled download is in progress")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	internal := s.Internal.(*jobapi.Server)
	items, base, err := internal.LegacyPublished(r, id)
	if err != nil {
		fail(w, 409, "history_unavailable", "unsupported format, unpublished job or changed original; use the original read-only environment")
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	if list {
		if s.audit(ctx, p, "", id, "legacy_artifact_list", "ok") != nil {
			fail(w, 503, "audit_unavailable", "read audit unavailable")
			return
		}
		respond(w, 200, map[string]any{"job_id": id, "artifacts": items, "synthetic": true, "read_only": true})
		return
	}
	for _, item := range items {
		if item.Path != parts[4] {
			continue
		}
		response := http.NewResponseController(w)
		if e := response.SetWriteDeadline(time.Now().Add(120 * time.Second)); e != nil {
			fail(w, 503, "download_deadline_unavailable", "controlled download requires a bounded connection deadline")
			return
		}
		defer response.SetWriteDeadline(time.Time{})
		file, e := internal.OpenLegacyArtifact(r, base, item)
		if e != nil {
			fail(w, 409, "history_changed", "artifact integrity check failed")
			return
		}
		defer file.Close()
		if s.audit(ctx, p, "", id, "legacy_artifact_download", "ok", item.Path) != nil {
			fail(w, 503, "audit_unavailable", "download audit unavailable")
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename=\""+item.Path+"\"")
		http.ServeContent(w, r, item.Path, time.Time{}, file)
		return
	}
	fail(w, 404, "not_found", "no such member in the verified inventory")
}
