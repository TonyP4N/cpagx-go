package jobapi

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthenticationAndConfinement(t *testing.T) {
	if _, err := New(jobs.Repository{}, "", "123456789012345678901234"); err == nil {
		t.Fatal("missing shared root accepted")
	}
	root := t.TempDir()
	h, err := New(jobs.Repository{}, root, "123456789012345678901234")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/jobs/test", nil))
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	s := h.(*Server)
	for _, p := range []string{"../escape", "/tmp/file", "a/../b", "a\\b"} {
		if _, err = s.file(p); err == nil {
			t.Fatal(p)
		}
	}
	if err = os.Symlink("/tmp", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.file("link"); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err = New(jobs.Repository{}, root, "short"); err == nil {
		t.Fatal("weak secret")
	}
}

func TestPayloadFingerprintAndBytes(t *testing.T) {
	root := t.TempDir()
	h, err := New(jobs.Repository{}, root, "123456789012345678901234")
	if err != nil {
		t.Fatal(err)
	}
	s := h.(*Server)
	profile := []byte(`{"z":1,"name":"中文","a":{"b":true}}`)
	sum := sha256.Sum256(profile)
	ref := Ref{Path: "inputs/profile.json", SHA: hex.EncodeToString(sum[:])}
	if err = os.WriteFile(filepath.Join(root, ref.Path), profile, 0400); err != nil {
		t.Fatal(err)
	}
	canonical := []byte(`{"a":{"b":true},"name":"中文","z":1}`)
	fp := sha256.Sum256(canonical)
	p := Payload{Network: ref, Process: ref, Profile: ref, Fingerprint: hex.EncodeToString(fp[:])}
	if err = s.validPayload(p); err != nil {
		t.Fatal(err)
	}
	p.Fingerprint = strings.Repeat("0", 64)
	if err = s.validPayload(p); err == nil {
		t.Fatal("wrong fingerprint accepted")
	}
	p.Fingerprint = hex.EncodeToString(fp[:])
	p.Network.SHA = strings.Repeat("0", 64)
	if err = s.validPayload(p); err == nil {
		t.Fatal("wrong bytes accepted")
	}
}
