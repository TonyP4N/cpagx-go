package jobs

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"time"
)

var dispatchIdentity = regexp.MustCompile(`^[0-9a-f]{32}$`)
var ErrDispatchBusy = errors.New("dispatch temporarily unavailable")

type Dispatch struct {
	JobID      string `json:"job_id"`
	DispatchID string `json:"dispatch_id"`
	Partition  string `json:"partition"`
	LeaseToken string `json:"lease_token"`
}

func newDispatchLease() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}

// LeaseDispatches does not acknowledge a broker publish. An expired lease can be
// retried with the same dispatch identity; late confirmations are fenced.
func (r Repository) LeaseDispatches(ctx context.Context, publisher string, lease time.Duration, limit int) ([]Dispatch, error) {
	if publisher == "" || len(publisher) > 100 || lease < time.Second || lease > 5*time.Minute || limit < 1 || limit > 100 {
		return nil, errors.New("invalid publisher lease")
	}
	token, err := newDispatchLease()
	if err != nil {
		return nil, err
	}
	rows, err := r.DB.QueryContext(ctx, `WITH candidate AS (
 SELECT o.dispatch_id FROM m4_dispatch_outbox o JOIN m4_jobs j ON j.id=o.job_id
 WHERE o.confirmed_at IS NULL AND o.invalidated_at IS NULL AND (o.leased_until IS NULL OR o.leased_until<=clock_timestamp())
 AND j.state='queued' AND j.dispatch_partition='rabbit-v3' AND j.dispatch_id=o.dispatch_id AND j.available_at<=clock_timestamp()
 ORDER BY o.created_at,o.dispatch_id FOR UPDATE OF o SKIP LOCKED LIMIT $4)
 UPDATE m4_dispatch_outbox o SET publisher=$1,lease_token=$2,leased_until=clock_timestamp()+($3*interval '1 millisecond'),publish_attempts=publish_attempts+1 FROM candidate c WHERE o.dispatch_id=c.dispatch_id
 RETURNING o.job_id,o.dispatch_id,o.partition,o.lease_token`, publisher, token, lease.Milliseconds(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Dispatch{}
	for rows.Next() {
		var d Dispatch
		if err = rows.Scan(&d.JobID, &d.DispatchID, &d.Partition, &d.LeaseToken); err != nil {
			return nil, err
		}
		result = append(result, d)
	}
	return result, rows.Err()
}
func (r Repository) ConfirmDispatch(ctx context.Context, id, publisher, token string) error {
	if !dispatchIdentity.MatchString(id) || publisher == "" || !digest.MatchString(token) {
		return errors.New("invalid dispatch confirmation")
	}
	return affected(r.DB.ExecContext(ctx, `UPDATE m4_dispatch_outbox SET confirmed_at=coalesce(confirmed_at,clock_timestamp()) WHERE dispatch_id=$1 AND publisher=$2 AND lease_token=$3 AND leased_until>clock_timestamp() AND invalidated_at IS NULL`, id, publisher, token))
}

// RollbackDispatch changes only unclaimed queued tasks. A running attempt keeps
// its partition, lease, token and execution lifecycle unchanged.
func (r Repository) RollbackDispatch(ctx context.Context, ids []string) ([]string, error) {
	if len(ids) < 1 || len(ids) > 1000 {
		return nil, errors.New("bounded explicit job list required")
	}
	for _, id := range ids {
		if !dispatchIdentity.MatchString(id) {
			return nil, errors.New("invalid rollback job identity")
		}
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result := []string{}
	// Stable ordering also prevents two overlapping rollback lists deadlocking.
	unique := map[string]bool{}
	for _, id := range ids {
		unique[id] = true
	}
	ordered := make([]string, 0, len(unique))
	for id := range unique {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		var changed string
		err = tx.QueryRowContext(ctx, `UPDATE m4_jobs SET dispatch_partition='poll' WHERE id=$1 AND state='queued' AND dispatch_partition='rabbit-v3' RETURNING id`, id).Scan(&changed)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, changed)
	}
	return result, tx.Commit()
}
