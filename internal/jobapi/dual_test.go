package jobapi

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPythonCanonicalFractionalFingerprints(t *testing.T) {
	cases := []struct{ raw, expected string }{
		{`{"window_seconds":0.5,"offset_seconds":1.0}`, "b7a1b640c789affe6ffd95a2a1e7a9f599a235863c314cf1c59b7db7288976f4"},
		{`{"a":-0.0,"b":0.0001,"c":1e-5}`, "a521482b1fdf78cf5afa781f2262679baa7ad0197eb8bbbdaed76e7c5c8ffc92"},
		{`{"a":1.2345678901234567,"b":1e16}`, "9992c0eeb8d4725b5a9a6f66489852ff3fdf989e8ccba548e6d5deaaa21e4e68"},
		{`{"x":"中文<>&","y":0.000001}`, "23f40a7eded020654e1ad7a3ca6bb837c99c77fc2b43ea7825954f3fe5ec4efa"},
		{`{"x":"a\u2028b\u2029c"}`, "02c8598f2d595b9e88439011d18c964d2feb930ca9b141591669e911fee12c6e"},
		{`{"x":"\\u2028 and \\u003c"}`, "1cbc93a974d8b30e247efef20e140d9df7abc43aedd63c4f4983903e3a80789d"},
		{`{"x":"\\u003c","y":"\\u2028","z":"<>&"}`, "7a9aa2bb133e050e6706c86892f4c9b931754933eb127fc66b187b5ecde7d656"},
		{`{"x":"a\u2028b\\u2029c"}`, "5d222805d0bbceea1681a304d80df335f59f2c7c48a1e285920bec11bd6171f2"},
		{`{"x":"\u0000\b\f\n\r\t\"\\"}`, "ebff1bb96d6a583776208a495591013d22916a8de6f015d3de5c87e939d5d3ec"},
	}
	for _, tc := range cases {
		value, err := parseValue([]byte(tc.raw))
		if err != nil {
			t.Fatal(err)
		}
		got, err := digestValue(value)
		if err != nil || got != tc.expected {
			t.Fatalf("%s: got %s, %v", tc.raw, got, err)
		}
	}
}

func TestDualArtifactPathsAndInventory(t *testing.T) {
	for _, name := range dualFiles {
		if !validArtifactPath(name, "dual-source") {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"dual/../events.json", "dual/unknown.json", "../events.json", "dual/sources/network.pcap/extra", "manifest.json"} {
		if validArtifactPath(name, "dual-source") {
			t.Fatal("accepted " + name)
		}
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := "jobs/test/attempt-1/"
	if err := os.MkdirAll(filepath.Join(root, base, "dual/sources"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range dualFiles {
		path := filepath.Join(root, base, name)
		if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{Root: root}
	if err := s.dualInventory(base); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, base, "dual/extra"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.dualInventory(base); err == nil {
		t.Fatal("extra nested file accepted")
	}
	if err := os.Remove(filepath.Join(root, base, "dual/extra")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, base, "manifest.json"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	anchor := strings.Repeat("a", 64) + ".json"
	if err := os.WriteFile(filepath.Join(root, base, anchor), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.dualInventory(base); err != nil {
		t.Fatalf("published anchor rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, base, strings.Repeat("b", 64)+".json"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.dualInventory(base); err == nil {
		t.Fatal("second publication anchor accepted")
	}
	if err := os.Remove(filepath.Join(root, base, strings.Repeat("b", 64)+".json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, base, "dual/sources/process.csv")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, base, "events.json"), filepath.Join(root, base, "dual/sources/process.csv")); err != nil {
		t.Fatal(err)
	}
	if err := s.dualInventory(base); err == nil {
		t.Fatal("nested symlink accepted")
	}
}

func TestDualRawReferenceTampering(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := "jobs/test/attempt-1/"
	if err := os.MkdirAll(filepath.Join(root, base, "dual/sources"), 0700); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 41)
	copy(frame, []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint16(frame[4:], 2)
	binary.LittleEndian.PutUint16(frame[6:], 4)
	binary.LittleEndian.PutUint32(frame[16:], 65535)
	binary.LittleEndian.PutUint32(frame[20:], 1)
	binary.LittleEndian.PutUint32(frame[32:], 1)
	binary.LittleEndian.PutUint32(frame[36:], 1)
	frame[40] = 'x'
	csv := []byte("time,pump\n2026-01-01T00:00:00Z,1\n")
	networkSHA := sha256.Sum256(frame)
	processSHA := sha256.Sum256(csv)
	oneSHA := sha256.Sum256([]byte("x"))
	nsha, psha := hex.EncodeToString(networkSHA[:]), hex.EncodeToString(processSHA[:])
	if err := os.WriteFile(filepath.Join(root, base, "dual/sources/network.pcap"), frame, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, base, "dual/sources/process.csv"), csv, 0600); err != nil {
		t.Fatal(err)
	}
	profile := map[string]any{"process": map[string]any{"timestamp_column": "time"}}
	b, _ := json.Marshal(profile)
	if err := os.WriteFile(filepath.Join(root, base, "dual/sources/profile.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	networkRef := map[string]any{"file_sha256": nsha, "frame_number": json.Number("1"), "record_number": nil, "column": nil, "raw_time": "0"}
	processRef := map[string]any{"file_sha256": psha, "frame_number": nil, "record_number": json.Number("1"), "column": "pump", "raw_time": "2026-01-01T00:00:00Z"}
	slice := map[string]any{"source_ref": networkRef, "frame_byte_offset": json.Number("0"), "length": json.Number("1"), "hex": "78", "sha256": hex.EncodeToString(oneSHA[:])}
	analysis := map[string]any{"network": []any{map[string]any{"observation": map[string]any{"source_refs": []any{networkRef}, "fields": map[string]any{"value": map[string]any{"slices": []any{slice}}}}}}, "process": []any{map[string]any{"event": map[string]any{"source_ref": processRef}}}}
	p := Payload{Network: Ref{SHA: nsha}, Process: Ref{SHA: psha}}
	s := &Server{Root: root}
	if err := s.validateDualReferences(base, p, analysis, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	networkRef["raw_time"] = "1"
	if err := s.validateDualReferences(base, p, analysis, map[string]any{}); err == nil {
		t.Fatal("changed frame reference accepted")
	}
	networkRef["raw_time"] = "0"
	processRef["record_number"] = json.Number("2")
	if err := s.validateDualReferences(base, p, analysis, map[string]any{}); err == nil {
		t.Fatal("out-of-range CSV reference accepted")
	}
	processRef["record_number"] = json.Number("1")
	slice["hex"] = strings.Repeat("0", 2)
	if err := s.validateDualReferences(base, p, analysis, map[string]any{}); err == nil {
		t.Fatal("wrong original field bytes accepted")
	}
}

func TestDualExportFromCore(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(repo, ".venv/bin/python")
	if _, err := os.Stat(python); err != nil {
		python, err = exec.LookPath("python3")
		if err != nil {
			t.Skip("Python fixture runtime unavailable")
		}
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	script := `from pathlib import Path
import json,sys
from dual_source_fixtures import make_case
from cpag_core.dual_source_export import export_task
root=Path(sys.argv[1]); paths=make_case(root/'inputs')
profile=json.loads(paths[2].read_text()); profile['window_seconds']=0.5; profile['clocks']['network']['offset_seconds']=0.25
paths[2].write_text(json.dumps(profile))
(root/'jobs/test').mkdir(parents=True)
export_task(*paths,root/'jobs/test/attempt-1')`
	cmd := exec.Command(python, "-c", script, root)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "services/analysis/src")+":"+filepath.Join(repo, "scripts/validation"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dual core export failed: %v: %s", err, output)
	}
	s := &Server{Root: root}
	base := "jobs/test/attempt-1/"
	ref := func(name string) Ref {
		b, err := os.ReadFile(filepath.Join(root, "inputs", name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		return Ref{Path: "inputs/" + name, SHA: hex.EncodeToString(sum[:])}
	}
	names := []string{}
	entries, err := os.ReadDir(filepath.Join(root, "inputs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	var p Payload
	p.Kind = "dual-source"
	for _, name := range names {
		switch filepath.Ext(name) {
		case ".pcap", ".pcapng":
			p.Network = ref(name)
		case ".csv":
			p.Process = ref(name)
		case ".json":
			p.Profile = ref(name)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, base, "run_manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	core, err := parseValue(raw)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := obj(core)
	manifest["run_id"] = "test"
	manifest["attempt_id"] = json.Number("1")
	p.Fingerprint = str(manifest["config_fingerprint"])
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, base, "run_manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.validPayload(p); err != nil {
		t.Fatalf("dual profile rejected: %v", err)
	}
	if err = s.validateDual(base, p, Manifest{}, raw); err != nil {
		t.Fatalf("valid core export rejected: %v", err)
	}
	// Rehashed analysis content must still be grounded in the original source.
	value, err := s.readDualJSON(base, "analysis.json")
	if err != nil {
		t.Fatal(err)
	}
	analysis, _ := obj(value)
	network, _ := arr(analysis["network"])
	row, _ := obj(network[0])
	event, _ := obj(row["event"])
	source, _ := obj(event["source_ref"])
	source["raw_time"] = "999"
	altered, _ := json.Marshal(analysis)
	for _, name := range []string{"analysis.json", "dual/analysis.json"} {
		if err = os.WriteFile(filepath.Join(root, base, name), altered, 0600); err != nil {
			t.Fatal(err)
		}
	}
	dual, err := s.readDualJSON(base, "dual/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	dm, _ := obj(dual)
	files, _ := obj(dm["files"])
	sum := sha256.Sum256(altered)
	files["analysis.json"] = hex.EncodeToString(sum[:])
	updated, _ := json.Marshal(dm)
	if err = os.WriteFile(filepath.Join(root, base, "dual/manifest.json"), updated, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.validateDual(base, p, Manifest{}, raw); err == nil {
		t.Fatal("self-rehashed unsupported analysis accepted")
	}
}
