package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalOrigin(t *testing.T) {
	for _, s := range []string{"http://127.0.0.1:123@evil.example", "http://example.com:123", "http://127.0.0.1:123/?token=x", "file:///tmp/x"} {
		if _, e := localOrigin(s); e == nil {
			t.Fatal(s)
		}
	}
}
func TestSessionIsOriginBoundAndPrivate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "session.json")
	if e := saveSession(p, storedSession{"cpag_session=user-only", "http://127.0.0.1:123"}); e != nil {
		t.Fatal(e)
	}
	if _, e := loadSession(p, "http://127.0.0.1:124"); e == nil {
		t.Fatal("origin reuse")
	}
	os.Chmod(p, 0644)
	if _, e := loadSession(p, "http://127.0.0.1:123"); e == nil {
		t.Fatal("public session")
	}
}
func TestSamePublicSemantics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v3/session" {
			http.SetCookie(w, &http.Cookie{Name: "cpag_session", Value: "opaque", HttpOnly: true})
			w.Write([]byte(`{"user":{"role":"viewer"}}`))
			return
		}
		c, e := r.Cookie("cpag_session")
		if e != nil || c.Value != "opaque" {
			t.Error("no user session")
		}
		w.WriteHeader(403)
		w.Write([]byte(`{"error":{"code":"forbidden","message":"read only"}}`))
	}))
	defer server.Close()
	p := filepath.Join(t.TempDir(), "session")
	var b bytes.Buffer
	if e := run([]string{"--url", server.URL, "--session", p, "login"}, strings.NewReader(`{"username":"a","password":"secret"}`), &b); e != nil {
		t.Fatal(e)
	}
	b.Reset()
	if e := run([]string{"--url", server.URL, "--session", p, "request", "POST", "/api/v3/runs"}, strings.NewReader(`{}`), &b); e == nil || !strings.Contains(b.String(), "forbidden") {
		t.Fatal(e, b.String())
	}
	if strings.Contains(b.String(), "opaque") || strings.Contains(b.String(), "secret") {
		t.Fatal("credential exposure")
	}
}
