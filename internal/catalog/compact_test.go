package catalog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TonyP4N/cpagx-go/internal/jobapi"
)

func TestCompactProjectionUsesTypedInternalCodeNotDiagnosticWords(t *testing.T) {
	for _, tc := range []struct {
		code, diagnostic string
		status           int
	}{
		{"result_changed", "prepared artifact byte budget or size mismatch", 409},
		{"result_changed", "service_storage_budget_mismatch", 409},
		{"query_limit", "bounded page selection mismatch", 422},
		{"verification_pending", "background source verifier active", 409},
		{"query_timeout", "controlled read expired", 504},
		{"", "unrecognized budget outside mismatch diagnostic", 409},
	} {
		t.Run(tc.code+tc.diagnostic, func(t *testing.T) {
			internal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]string{"code": tc.code, "error": tc.diagnostic})
			})
			s := &Server{Internal: internal}
			w := httptest.NewRecorder()
			s.compactProjection(w, httptest.NewRequest("GET", "/api/v3/runs/run/shared-query?action=metadata", nil), nil, "dataset", "run")
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var response struct {
				Error apiError `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			want := tc.code
			if want == "" {
				want = "result_unavailable"
			}
			if response.Error.Code != want {
				t.Fatalf("code=%s want=%s body=%s", response.Error.Code, want, w.Body.String())
			}
		})
	}
}
func TestCompactPagePlusOneTravelsThroughInternalHTTPCode(t *testing.T) {
	internal := &jobapi.Server{Secret: "private-service-token-123456789"}
	s := &Server{Internal: internal, cfg: Config{WorkerToken: internal.Secret}}
	w := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/v3/runs/run/shared-query?action=page&logical_root=analysis.json&limit=101", nil)
	s.compactProjection(w, request, nil, "dataset", "run")
	if w.Code != 422 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
