package jobapi

import (
	"strings"
	"testing"
)

func TestComposeVerifierSourceIdentityIsExplicitBackendOnly(t *testing.T) {
	image := "sha256:" + strings.Repeat("a", 64)
	source := "source-sha256:" + strings.Repeat("b", 64)
	for _, backend := range []string{"", "kube-sidecar-v1"} {
		t.Setenv("CPAG_VERIFY_BACKEND", backend)
		if !ValidCompactVerifierIdentity(image) || ValidCompactVerifierIdentity(source) {
			t.Fatal("legacy image trust changed", backend)
		}
	}
	t.Setenv("CPAG_VERIFY_BACKEND", "compose-file-sidecar-v1")
	if !ValidCompactVerifierIdentity(source) || ValidCompactVerifierIdentity(image) || ValidCompactVerifierImage(source) {
		t.Fatal("Compose source identity escaped backend boundary")
	}
	if e := VerifyComposeVerifierBundle("source-sha256:"+strings.Repeat("f", 64), "python3"); e == nil {
		t.Fatal("unmatched or unavailable bundle accepted")
	}
}
