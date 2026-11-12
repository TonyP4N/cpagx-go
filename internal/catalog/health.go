package catalog

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const minimumReadyFreeBytes uint64 = 64 << 20

type storageHealth struct {
	Name       string `json:"name"`
	Accessible bool   `json:"accessible"`
	FreeBytes  uint64 `json:"free_bytes"`
	TotalBytes uint64 `json:"total_bytes"`
	Reason     string `json:"reason,omitempty"`
}

// No probes are written inside immutable publication/source inventories.
func checkStorage(name, path string) storageHealth {
	value := storageHealth{Name: name}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		value.Reason = "storage_directory_unavailable"
		return value
	}
	physical, err := filepath.EvalSymlinks(path)
	if err != nil || physical != filepath.Clean(path) || syscall.Access(path, 4|2|1) != nil {
		value.Reason = "storage_access_unavailable"
		return value
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(path, &fs) != nil {
		value.Reason = "storage_space_unavailable"
		return value
	}
	value.FreeBytes = uint64(fs.Bavail) * uint64(fs.Bsize)
	value.TotalBytes = uint64(fs.Blocks) * uint64(fs.Bsize)
	if uint64(fs.Flags)&uint64(1) != 0 {
		value.Reason = "storage_read_only"
		return value
	}
	value.Accessible = true
	if value.FreeBytes < minimumReadyFreeBytes {
		value.Reason = "storage_space_low"
	}
	return value
}
func (s *Server) storageHealth() []storageHealth {
	return []storageHealth{checkStorage("shared_inputs", filepath.Join(s.Root, "inputs")), checkStorage("catalog_inputs", filepath.Join(s.Root, "inputs", "catalog")), checkStorage("shared_jobs", filepath.Join(s.Root, "jobs")), checkStorage("control", s.cfg.ControlRoot)}
}
func (s *Server) serveHealth(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/health/live" && r.URL.Path != "/health/ready" {
		return false
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		fail(w, 405, "method_not_allowed", "health checks require GET or HEAD")
		return true
	}
	if r.URL.Path == "/health/live" {
		respond(w, 200, map[string]string{"status": "live"})
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	database := s.DB != nil && s.DB.PingContext(ctx) == nil
	storage := true
	for _, row := range s.storageHealth() {
		if !row.Accessible || row.Reason != "" {
			storage = false
		}
	}
	status, code := "ready", 200
	if !database || !storage {
		status = "not_ready"
		code = 503
	}
	// Public probes disclose neither physical paths nor database errors/credentials.
	respond(w, code, map[string]any{"status": status, "checks": map[string]bool{"database": database, "storage": storage}})
	return true
}
