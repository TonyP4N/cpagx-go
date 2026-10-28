package jobapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/TonyP4N/cpagx-go/internal/capacity"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCapacityAndResourceBindingsFailClosed(t *testing.T) {
	s := &Server{CapacityPolicy: capacity.Engineering, ResourceProfile: capacity.DevelopmentS100}
	doc := map[string]any{"capacity_profile": capacity.Engineering, "analysis_mode": "bounded-real-capable-v1"}
	p := Payload{Kind: "dual-source", CapacityProfile: capacity.Engineering, ResourceProfile: capacity.DevelopmentS100}
	if _, err := s.payloadBudget(p, doc); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Payload){func(p *Payload) { p.CapacityProfile = "" }, func(p *Payload) { p.ResourceProfile = "" }, func(p *Payload) { p.Kind = "dual-source-replay" }} {
		bad := p
		change(&bad)
		if _, err := s.payloadBudget(bad, doc); err == nil {
			t.Fatalf("unbound payload accepted: %+v", bad)
		}
	}
	s.CapacityPolicy = ""
	if _, err := s.payloadBudget(p, doc); err == nil {
		t.Fatal("operator policy omitted")
	}
}

func TestCSVLogicalBudgetDoesNotCountQuotedNewlinesAsRecords(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	if err := os.Mkdir(filepath.Join(root, "inputs"), 0700); err != nil {
		t.Fatal(err)
	}
	s := &Server{Root: root}
	p := Payload{Process: Ref{Path: "inputs/process.csv"}}
	b, _ := capacity.Resolve(capacity.Engineering)
	write := func(rows int, cols int) {
		var out bytes.Buffer
		out.WriteString(strings.TrimSuffix(strings.Repeat("column,", cols), ",") + "\n")
		for i := 0; i < rows; i++ {
			out.WriteString("\"one\ntwo\"" + strings.Repeat(",value", cols-1) + "\n")
		}
		if err := os.WriteFile(filepath.Join(root, p.Process.Path), out.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(10000, 16)
	if err := s.validateProcessBudget(p, b); err != nil {
		t.Fatal(err)
	}
	write(10001, 16)
	if err := s.validateProcessBudget(p, b); err == nil {
		t.Fatal("+1 logical record accepted")
	}
	write(1, 17)
	if err := s.validateProcessBudget(p, b); err == nil {
		t.Fatal("+1 column accepted")
	}
}

func TestOperatorArtifactGuardPreservesInputAndOldLimits(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(root, "artifact.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate((64 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	ref := Ref{Path: "artifact.json", SHA: fmt.Sprintf("%x", hash)}
	s := &Server{Root: root, ResourceProfile: capacity.DevelopmentS100}
	if _, err = s.check(ref); err == nil {
		t.Fatal("old/input64MiB guard increased")
	}
	if _, err = s.checkArtifact(Payload{ResourceProfile: capacity.DevelopmentS100}, ref); err != nil {
		t.Fatal(err)
	}
	if _, err = s.checkArtifact(Payload{}, ref); err == nil {
		t.Fatal("unbound old payload used new output allowance")
	}
}

func TestHistoricalPayloadReadableUnderNewOperatorWithoutRelaxingSubmission(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	if err := os.Mkdir(filepath.Join(root, "inputs"), 0700); err != nil {
		t.Fatal(err)
	}
	profile, err := os.ReadFile("../../profiles/dual-source-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	ref := func(name string, raw []byte) Ref {
		if err := os.WriteFile(filepath.Join(root, "inputs", name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		return Ref{Path: "inputs/" + name, SHA: hex.EncodeToString(digest[:])}
	}
	fingerprint, err := DualProfileFingerprint(profile)
	if err != nil {
		t.Fatal(err)
	}
	p := Payload{Kind: "dual-source", Network: ref("network.pcap", []byte("original capture")),
		Process: ref("process.csv", []byte("time,pump\n2026-01-01T00:00:00Z,0\n")), Profile: ref("profile.json", profile), Fingerprint: fingerprint}
	s := &Server{Root: root, ResourceProfile: capacity.DevelopmentS100, CapacityPolicy: capacity.Engineering}
	if err := s.validPayload(p); err == nil {
		t.Fatal("new submission used old/mismatched operator resource binding")
	}
	if err := s.validHistoricalPayload(p); err != nil {
		t.Fatalf("old historical input under new operator: %v", err)
	}
	old, err := s.artifactLimit(p)
	if err != nil || old != 64<<20 {
		t.Fatalf("old artifact budget reinterpreted: %d %v", old, err)
	}
	p.ResourceProfile = "unknown-historical-resource"
	if err := s.validHistoricalPayload(p); err == nil {
		t.Fatal("unknown historical resource version accepted")
	}
}
