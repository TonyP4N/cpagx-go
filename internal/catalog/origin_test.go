package catalog

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestR21ExternalOrigin(t *testing.T) {
	for _, origin := range []string{"", "https://cpag.example.org", "https://lab.test:8443"} {
		if err := validateExternalOrigin(origin); err != nil {
			t.Errorf("valid %q: %v", origin, err)
		}
	}
	for _, origin := range []string{"https://", "http://lab.test", "https://lab.test/", "https://lab.test?", "https://lab.test#", "https://a@lab.test", "https://*.test", "https://Lab.test", "https://lab.test:443", "https://lab.test:99999"} {
		if validateExternalOrigin(origin) == nil {
			t.Errorf("accepted %q", origin)
		}
	}
	c := Config{PublicAddr: "127.0.0.1:8095", ExternalOrigin: "https://cpag.example.org"}
	for _, tc := range []struct {
		name            string
		origins         []string
		site, forwarded string
		want            bool
	}{
		{"login", []string{c.ExternalOrigin}, "same-origin", "", true},
		{"other", []string{"https://foreign.test"}, "", "https", false},
		{"old local origin", []string{"http://127.0.0.1:8095"}, "", "", false},
		{"duplicate", []string{c.ExternalOrigin, c.ExternalOrigin}, "", "", false},
		{"opaque", []string{"null"}, "", "", false},
		{"forged even with matching Origin", []string{c.ExternalOrigin}, "same-origin", "http", false},
		{"forged proto", nil, "", "https", false},
		{"cross site", []string{c.ExternalOrigin}, "cross-site", "", false},
		{"missing browser origin", nil, "same-site", "", false},
		{"command line", nil, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v3/session", strings.NewReader("{}"))
			for _, o := range tc.origins {
				r.Header.Add("Origin", o)
			}
			r.Header.Set("Sec-Fetch-Site", tc.site)
			if tc.forwarded != "" {
				r.Header.Set("X-Forwarded-Proto", tc.forwarded)
			}
			if c.allowsWrite(r) != tc.want {
				t.Fatalf("origin acceptance should be %v", tc.want)
			}
		})
	}
}
