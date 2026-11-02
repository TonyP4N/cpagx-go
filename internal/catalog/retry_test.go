package catalog

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// Authorization precedes binding diagnostics. Historical reconstructions are
// readable but cannot become admissions merely by clicking retry.
func TestRetryAdmissionBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name, role, body string
		native           bool
		code             int
	}{
		{"viewer", "viewer", `{"expected_attempt":1}`, false, 403},
		{"historical binding", "admin", `{"expected_attempt":1}`, false, 409},
		{"missing expected attempt", "admin", `{}`, true, 422},
		{"negative attempt", "admin", `{"expected_attempt":-1}`, true, 422},
		{"forged configuration", "admin", `{"expected_attempt":1,"config_version_id":"other"}`, true, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{}
			w := httptest.NewRecorder()
			s.retryRun(w, httptest.NewRequest("POST", "/api/v3/runs/example/retry", strings.NewReader(tc.body)), &principal{Role: tc.role}, "dataset", "example", tc.native)
			if w.Code != tc.code {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.code, w.Body.String())
			}
		})
	}
}
