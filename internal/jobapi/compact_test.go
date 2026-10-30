package jobapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TonyP4N/cpagx-go/internal/capacity"
)

func compactFixture(t *testing.T) (*Server, Payload, string, string) {
	t.Helper()
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	base := "jobs/test/attempt-1/"
	p := Payload{Kind: "dual-source", CapacityProfile: capacity.EngineeringCore, StorageFormat: capacity.CoreSharedFormat, StorageBudgetVersion: SharedStorageBudget, ResourceProfile: capacity.StorageBudget, Fingerprint: strings.Repeat("a", 64)}
	s := &Server{Root: root}
	for _, dir := range []string{"shared", "sources"} {
		if err := os.MkdirAll(filepath.Join(root, base, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, data []byte) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, base, name), data, 0400); err != nil {
			t.Fatal(err)
		}
		return bytesSHA(data)
	}
	p.Network = Ref{Path: "inputs/network.pcap", SHA: write("sources/network.pcap", []byte("network"))}
	p.Process = Ref{Path: "inputs/process.csv", SHA: write("sources/process.csv", []byte("time,value\n1,1\n"))}
	p.Profile = Ref{Path: "inputs/profile.json", SHA: write("sources/profile.json", []byte(`{}`))}
	write("shared/manifest.json", []byte(`{}`))
	write("shared/shared.sqlite3", []byte("placeholder: structural validation is the Python source verifier's job"))
	m := Manifest{RunID: "test", AttemptID: 1, CapacityProfile: p.CapacityProfile, ResourceProfile: p.ResourceProfile, StorageBudgetVersion: p.StorageBudgetVersion, StorageFormat: p.StorageFormat, Fingerprint: p.Fingerprint, Inputs: map[string]string{"network": p.Network.SHA, "process": p.Process.SHA, "profile": p.Profile.SHA}}
	artifacts := []map[string]any{}
	for _, name := range compactArtifactNames(p) {
		if name == "run_manifest.json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, base, name))
		if err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, map[string]any{"path": name, "sha256": bytesSHA(raw), "size_bytes": len(raw)})
	}
	core, _ := json.Marshal(map[string]any{"run_id": "test", "attempt_id": 1, "config_fingerprint": p.Fingerprint, "mode": "offline", "storage_format": p.StorageFormat, "artifacts": artifacts})
	write("run_manifest.json", core)
	for _, name := range compactArtifactNames(p) {
		raw, err := os.ReadFile(filepath.Join(root, base, name))
		if err != nil {
			t.Fatal(err)
		}
		m.Artifacts = append(m.Artifacts, struct {
			Path string `json:"path"`
			SHA  string `json:"sha256"`
			Size int64  `json:"size"`
		}{name, bytesSHA(raw), int64(len(raw))})
	}
	raw, _ := json.Marshal(m)
	sha := write("manifest.json", raw)
	return s, p, base, sha
}
func TestCompactWrapperExactInventoryAndRetainedOriginals(t *testing.T) {
	s, p, base, sha := compactFixture(t)
	if _, err := s.compactWrapper(context.Background(), base, p, sha); err != nil {
		t.Fatal(err)
	}
	// An expected hash is only a physical check, never a source approval.
	if len(s.compact.entries) != 0 {
		t.Fatal("physical validation created source approval")
	}
	if err := os.WriteFile(filepath.Join(s.Root, base, "FAILED.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.compactWrapper(context.Background(), base, p, sha); err == nil {
		t.Fatal("unlisted failure artifact accepted")
	}
	os.Remove(filepath.Join(s.Root, base, "FAILED.json"))
	if err := os.Chmod(filepath.Join(s.Root, base, "sources/process.csv"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Root, base, "sources/process.csv"), []byte("time,value\n1,2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.compactWrapper(context.Background(), base, p, sha); err == nil {
		t.Fatal("mutated retained source accepted")
	}
}
func TestCompactBindingCannotCrossOldVersions(t *testing.T) {
	s, p, base, sha := compactFixture(t)
	q := p
	q.StorageBudgetVersion = ""
	if _, err := s.compactWrapper(context.Background(), base, q, sha); err == nil {
		t.Fatal("implicit compact storage budget accepted")
	}
	config := map[string]any{"capacity_profile": capacity.EngineeringCore, "storage_format": capacity.CoreSharedFormat, "storage_budget_version": SharedStorageBudget, "analysis_mode": "bounded-real-capable-v1"}
	if _, err := readPayloadBudget(p, config); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Payload){func(p *Payload) { p.ResourceProfile = capacity.EngineeringShared }, func(p *Payload) { p.HistoryFormat = capacity.CoreSharedFormat }, func(p *Payload) { p.StorageFormat = capacity.SharedFormat }, func(p *Payload) { p.CapacityProfile = capacity.EngineeringShared }} {
		bad := p
		change(&bad)
		if _, err := readPayloadBudget(bad, config); err == nil {
			t.Fatalf("cross-version binding accepted: %+v", bad)
		}
	}
}
func TestCompactVerifierImageIsImmutableOperatorValue(t *testing.T) {
	for _, image := range []string{"latest", "worker:latest", "sha256:abc", "repo@sha256:" + strings.Repeat("g", 64)} {
		if ValidCompactVerifierImage(image) {
			t.Fatal(image)
		}
	}
	for _, image := range []string{"sha256:" + strings.Repeat("a", 64), "repo@sha256:" + strings.Repeat("0", 64)} {
		if !ValidCompactVerifierImage(image) {
			t.Fatal(image)
		}
	}
}
func TestCompactReadStateIsNotSharedAcrossServerRestart(t *testing.T) {
	first := &Server{}
	first.compact.initialized = true
	first.compact.entries = map[string]*compactApproval{"old": {approval: json.RawMessage(`{"mac":"untrusted"}`)}}
	fresh := &Server{Root: first.Root, Secret: first.Secret}
	if fresh.compact.initialized || len(fresh.compact.entries) != 0 {
		t.Fatal("source approval survived service restart")
	}
}

func TestCompactTamperSizeMismatchIsIntegrityFailureNotQueryBudget(t *testing.T) {
	s, p, base, sha := compactFixture(t)
	path := filepath.Join(s.Root, base, "sources/process.csv")
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("tampered\n")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.compactWrapper(context.Background(), base, p, sha)
	if err == nil || !strings.Contains(err.Error(), "prepared artifact byte budget or size mismatch") {
		t.Fatalf("unexpected internal tamper diagnostic: %v", err)
	}
	if code := CompactErrorCode(err); code != "result_changed" {
		t.Fatalf("tamper code=%q: %v", code, err)
	}
	t.Logf("reproduced tamper diagnostic: %v", err)
}

func TestCompactStructuredHelperFailureCodes(t *testing.T) {
	for _, tc := range []struct{ reason, code string }{
		{"service_storage_budget_mismatch", "result_changed"},
		{"shared_total_physical_limit", "result_changed"},
		{"service_snapshot_outside_history", "query_limit"},
		{"shared_array_index_invalid", "query_limit"},
		{"shared_array_extent_invalid", ""},
		{"shared_page_byte_limit", "query_limit"},
		{"shared_logical_byte_limit", "query_limit"},
		{"shared_store_deadline_exceeded", "query_timeout"},
		{"unknown_future_budget_error", ""},
	} {
		raw, _ := json.Marshal(map[string]string{"reason": tc.reason})
		if actual := CompactErrorCode(compactHelperError(raw)); actual != tc.code {
			t.Fatalf("%s: %s != %s", tc.reason, actual, tc.code)
		}
	}
}

func TestCompactChangedOrMissingPhysicalArtifactsKeepIntegrityCode(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		remove     bool
	}{
		{"retained_csv_same_size", "sources/process.csv", false},
		{"retained_csv_missing", "sources/process.csv", true},
		{"shared_database_same_size", "shared/shared.sqlite3", false},
		{"shared_database_missing", "shared/shared.sqlite3", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p, base, sha := compactFixture(t)
			path := filepath.Join(s.Root, base, tc.path)
			if tc.remove {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw[len(raw)-1] ^= 1
				if err = os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := s.compactWrapper(context.Background(), base, p, sha)
			if err == nil || CompactErrorCode(err) != "result_changed" {
				t.Fatalf("physical mutation was not integrity failure: %v code=%s", err, CompactErrorCode(err))
			}
		})
	}
}

func TestCompactPublicationCannotBeReboundToAnotherRunOrAttempt(t *testing.T) {
	for _, field := range []string{"wrapper_run", "wrapper_attempt", "core_run", "core_attempt", "configuration"} {
		t.Run(field, func(t *testing.T) {
			s, p, base, sha := compactFixture(t)
			var wrapper Manifest
			raw, err := os.ReadFile(filepath.Join(s.Root, base, "manifest.json"))
			if err != nil || json.Unmarshal(raw, &wrapper) != nil {
				t.Fatal(err)
			}
			corePath := filepath.Join(s.Root, base, "run_manifest.json")
			coreRaw, err := os.ReadFile(corePath)
			if err != nil {
				t.Fatal(err)
			}
			var core map[string]any
			if err = json.Unmarshal(coreRaw, &core); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "wrapper_run":
				wrapper.RunID = "another-run"
			case "wrapper_attempt":
				wrapper.AttemptID = 2
			case "core_run":
				core["run_id"] = "another-run"
			case "core_attempt":
				core["attempt_id"] = 2
			case "configuration":
				core["config_fingerprint"] = strings.Repeat("b", 64)
				wrapper.Fingerprint = strings.Repeat("b", 64)
			}
			coreRaw, err = json.Marshal(core)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(corePath, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(corePath, coreRaw, 0600); err != nil {
				t.Fatal(err)
			}
			for i := range wrapper.Artifacts {
				if wrapper.Artifacts[i].Path == "run_manifest.json" {
					wrapper.Artifacts[i].SHA = bytesSHA(coreRaw)
					wrapper.Artifacts[i].Size = int64(len(coreRaw))
				}
			}
			raw, err = json.Marshal(wrapper)
			if err != nil {
				t.Fatal(err)
			}
			wrapperPath := filepath.Join(s.Root, base, "manifest.json")
			if err = os.Chmod(wrapperPath, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(wrapperPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			sha = bytesSHA(raw)
			_, err = s.compactWrapper(context.Background(), base, p, sha)
			if err == nil || CompactErrorCode(err) != "result_changed" {
				t.Fatalf("cross-run/attempt/config accepted: %v", err)
			}
		})
	}
}
