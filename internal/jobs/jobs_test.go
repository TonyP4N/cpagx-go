package jobs

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestArtifactKey(t *testing.T) {
	sha := strings.Repeat("a", 64)
	for _, id := range []string{"", ".", "..", "a/b"} {
		if _, err := ArtifactKey(Claim{ID: id, Attempt: 1}, sha); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
	a, err := ArtifactKey(Claim{ID: "run1", Attempt: 1}, sha)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ArtifactKey(Claim{ID: "run1", Attempt: 2}, sha)
	if a == b {
		t.Fatal("attempts share publication destination")
	}
	if _, err := ArtifactKey(Claim{ID: "run1", Attempt: 1}, "bad"); err == nil {
		t.Fatal("accepted invalid digest")
	}
}

func TestRecoveryRejectsNonpositiveInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		var reported error
		Repository{}.RunRecovery(context.Background(), "", interval, func(err error) { reported = err })
		if reported == nil {
			t.Fatal("invalid interval accepted")
		}
	}
}

func TestMissingAttemptReceiptRejected(t *testing.T) {
	if err := VerifyExit(t.TempDir(), Claim{ID: "multi", Attempt: 2, Worker: "worker", Token: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("missing exit proof accepted")
	}
}
