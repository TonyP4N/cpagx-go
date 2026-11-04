package jobapi

import (
	"context"
	"errors"
	"log"
)

// Observation failure never changes claim/lease authority or legacy API behavior.
// Only the authenticated, validated successful claim/heartbeat paths call this.
func (s *Server) observeWorker(ctx context.Context, worker, kind string) {
	_, err := s.Repo.DB.ExecContext(ctx, `INSERT INTO m4_worker_observations(worker,last_seen,last_kind) VALUES($1,clock_timestamp(),$2) ON CONFLICT(worker) DO UPDATE SET last_seen=excluded.last_seen,last_kind=excluded.last_kind`, worker, kind)
	if err == nil {
		return
	}
	var code interface{ SQLState() string }
	if errors.As(err, &code) && code.SQLState() == "42P01" {
		return
	} // pre-017 databases remain supported
	log.Print("worker_observation_write_failed") // never credentials, paths, or submitted bytes
}
