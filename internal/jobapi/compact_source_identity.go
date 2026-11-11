package jobapi

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

// A source identity is permitted only for the explicit Compose file-sidecar
// backend. Docker and the existing Kubernetes backend retain immutable image pins.
func ValidCompactVerifierIdentity(value string) bool {
	if os.Getenv("CPAG_VERIFY_BACKEND") == "compose-file-sidecar-v1" {
		raw, ok := strings.CutPrefix(value, "source-sha256:")
		return ok && shaPattern.MatchString(raw)
	}
	return ValidCompactVerifierImage(value)
}
func VerifyComposeVerifierBundle(value, python string) error {
	if os.Getenv("CPAG_VERIFY_BACKEND") != "compose-file-sidecar-v1" {
		return nil
	}
	if !ValidCompactVerifierIdentity(value) {
		return errors.New("Compose verifier requires bundled source identity")
	}
	if python == "" {
		python = "python3"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Fixed trusted bundle paths; no request or broker message chooses code.
	raw, err := exec.CommandContext(ctx, python, "/opt/cpag/verifier_identity.py", "--root", "/opt/cpag").Output()
	if err != nil || strings.TrimSpace(string(raw)) != value {
		return errors.New("configured Compose verifier source identity differs from bundled code")
	}
	return nil
}
