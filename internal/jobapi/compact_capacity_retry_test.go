package jobapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/jobs"
)

func settledCompactEntry(t *testing.T, authority *compactAuthority, key string) *compactApproval {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		authority.mu.Lock()
		entry := authority.entries[key]
		settled := entry != nil && !entry.pending
		authority.mu.Unlock()
		if settled {
			return entry
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("compact verification callback did not settle")
	return nil
}

func TestCompactHistoricalReadRecoversAfterDurableCapacityBecomesIdle(t *testing.T) {
	var authority compactAuthority
	var busy atomic.Bool
	busy.Store(true)
	var calls atomic.Int32
	verify := func(context.Context) (json.RawMessage, error) {
		calls.Add(1)
		if busy.Load() {
			return nil, fmt.Errorf("admission refused: %w", jobs.ErrCompactCapacityBusy)
		}
		return json.RawMessage(`{"verified":"same-immutable-publication"}`), nil
	}
	const key = "historical-run/attempt-1+unchanged-publication"
	if approval, err := authority.approvalFor(key, verify); len(approval) != 0 || !errors.Is(err, ErrVerificationPending) {
		t.Fatalf("first read acquired authority: %s %v", approval, err)
	}
	entry := settledCompactEntry(t, &authority, key)
	if !errors.Is(entry.err, jobs.ErrCompactCapacityBusy) || len(entry.approval) != 0 {
		t.Fatal("busy admission was mistaken for source verification")
	}
	// Repeated browser reads during contention stay pending, without launching
	// unbounded Docker attempts or returning a permanent unavailable verdict.
	for i := 0; i < 10; i++ {
		if approval, err := authority.approvalFor(key, verify); len(approval) != 0 || !errors.Is(err, ErrVerificationPending) {
			t.Fatalf("busy read %d: %s %v", i, approval, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("cooldown launched %d verifiers", calls.Load())
	}
	busy.Store(false) // The active computation exits; the persistent gate is idle.
	authority.mu.Lock()
	entry.retryAt = time.Now().Add(-time.Second)
	authority.mu.Unlock()
	if approval, err := authority.approvalFor(key, verify); len(approval) != 0 || !errors.Is(err, ErrVerificationPending) {
		t.Fatalf("retry did not wait for full verification: %s %v", approval, err)
	}
	settledCompactEntry(t, &authority, key)
	approval, err := authority.approvalFor(key, verify)
	if err != nil || string(approval) != `{"verified":"same-immutable-publication"}` || calls.Load() != 2 {
		t.Fatalf("same publication did not recover after release: %s %v calls=%d", approval, err, calls.Load())
	}
}

func TestCompactRetryNeverReclassifiesSourceOrUnknownFailures(t *testing.T) {
	for _, rejected := range []error{
		ErrCompactSourceVerificationFailed, ErrCompactResultChanged,
		jobs.ErrStale, errors.New("unclassified transport or cleanup failure"),
	} {
		t.Run(rejected.Error(), func(t *testing.T) {
			var authority compactAuthority
			var calls atomic.Int32
			verify := func(context.Context) (json.RawMessage, error) { calls.Add(1); return nil, rejected }
			_, _ = authority.approvalFor("frozen", verify)
			settledCompactEntry(t, &authority, "frozen")
			for i := 0; i < 3; i++ {
				approval, err := authority.approvalFor("frozen", verify)
				if len(approval) != 0 || !errors.Is(err, rejected) || errors.Is(err, ErrVerificationPending) {
					t.Fatalf("source/unknown rejection became retry authority: %s %v", approval, err)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("non-admission failure retried %d times", calls.Load())
			}
		})
	}
}
