package jobs

import (
	"strings"
	"testing"
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
