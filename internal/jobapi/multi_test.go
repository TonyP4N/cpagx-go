package jobapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestOrderedCapturePayloadAndPublication(t *testing.T) {
	a := Ref{Path: "inputs/a.pcap", SHA: "a"}
	b := Ref{Path: "inputs/b.pcap", SHA: "b"}
	p := Payload{Kind: "dual-source", Network: a, Networks: []Ref{a, b}, Process: Ref{SHA: "p"}, Profile: Ref{SHA: "c"}}
	if _, e := p.networkRefs(); e != nil {
		t.Fatal(e)
	}
	if !publicationInputsMatch(p, map[string]string{"network": "a", "process": "p", "profile": "c"}, []string{"a", "b"}) {
		t.Fatal("ordered hashes rejected")
	}
	if publicationInputsMatch(p, map[string]string{"network": "a", "process": "p", "profile": "c"}, []string{"b", "a"}) {
		t.Fatal("reordered publication accepted")
	}
	p.Networks = []Ref{a, a}
	if _, e := p.networkRefs(); e == nil {
		t.Fatal("duplicate capture accepted")
	}
	p.Networks = []Ref{b, a}
	if _, e := p.networkRefs(); e == nil {
		t.Fatal("primary mismatch accepted")
	}
	p.Networks = []Ref{a, b, a, b, a}
	if _, e := p.networkRefs(); e == nil {
		t.Fatal("fifth capture accepted")
	}
	p.Networks = nil
	if _, e := p.networkRefs(); e != nil {
		t.Fatal("legacy scalar rejected")
	}
}

func TestBoundedRealAndSyntheticMultiCaptureExports(t *testing.T) {
	repo, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	python := filepath.Join(repo, ".venv/bin/python")
	if _, e = os.Stat(python); e != nil {
		t.Skip("Python fixture runtime unavailable")
	}
	for _, real := range []bool{false, true} {
		t.Run(map[bool]string{false: "synthetic", true: "real_unvalidated"}[real], func(t *testing.T) {
			root, e := filepath.EvalSymlinks(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			script := `from pathlib import Path
import json,sys,struct
from dual_source_fixtures import make_case
from round17_profile import profile
from cpag_core.dual_source_export import export_task
root=Path(sys.argv[1]); paths=make_case(root/'inputs')
raw=paths[0].read_bytes();cursor=24;records=[]
while cursor<len(raw):
 n=struct.unpack_from('<I',raw,cursor+8)[0];records.append(raw[cursor:cursor+16+n]);cursor+=16+n
if len(records)<2:raise ValueError('two frames required')
a=root/'inputs/a.pcap';b=root/'inputs/b.pcap'
a.write_bytes(raw[:24]+b''.join(records[:1]));b.write_bytes(raw[:24]+b''.join(records[1:]))
cfg=profile(synthetic=sys.argv[2]!='true',rules=True);paths[2].write_text(json.dumps(cfg))
(root/'jobs/test').mkdir(parents=True)
export_task([a,b],paths[1],paths[2],root/'jobs/test/attempt-1',run_id='test',attempt_id=1)
(root/'refs.json').write_text(json.dumps({'network':str(a.relative_to(root)),'other':str(b.relative_to(root)),'process':str(paths[1].relative_to(root)),'profile':str(paths[2].relative_to(root))}))`
			flag := "false"
			if real {
				flag = "true"
			}
			cmd := exec.Command(python, "-c", script, root, flag)
			cmd.Dir = repo
			cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "services/analysis/src")+":"+filepath.Join(repo, "scripts/validation"))
			if out, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("fixture export: %v: %s", e, out)
			}
			var names map[string]string
			raw, _ := os.ReadFile(filepath.Join(root, "refs.json"))
			if e = json.Unmarshal(raw, &names); e != nil {
				t.Fatal(e)
			}
			ref := func(name string) Ref {
				path := names[name]
				raw, e := os.ReadFile(filepath.Join(root, path))
				if e != nil {
					t.Fatal(e)
				}
				return Ref{path, shaBytes(raw)}
			}
			p := Payload{Kind: "dual-source", Network: ref("network"), Process: ref("process"), Profile: ref("profile")}
			p.Networks = []Ref{p.Network, ref("other")}
			raw, _ = os.ReadFile(filepath.Join(root, p.Profile.Path))
			p.Fingerprint, e = DualProfileFingerprint(raw)
			if e != nil {
				t.Fatal(e)
			}
			s := &Server{Root: root}
			if e = s.validPayload(p); e != nil {
				t.Fatal(e)
			}
			base := "jobs/test/attempt-1/"
			core, _ := os.ReadFile(filepath.Join(root, base, "run_manifest.json"))
			if e = s.validateDual(base, p, Manifest{}, core); e != nil {
				t.Fatalf("Go rejected multi export: %v", e)
			}
			v, e := s.readDualJSON(base, "analysis.json")
			if e != nil {
				t.Fatal(e)
			}
			analysis, _ := obj(v)
			if analysis["analysis_version"] != currentBoundedAnalysisVersion {
				t.Fatalf("new bounded export used %v", analysis["analysis_version"])
			}
			if e := validateDualPublicationVersion(str(analysis["analysis_version"]), false); e != nil {
				t.Fatal(e)
			}
			if analysis["synthetic"] == real {
				t.Fatal("source category changed")
			}
			findings, _ := arr(analysis["rule_findings"])
			if len(findings) == 0 {
				t.Fatal("finite fixture required")
			}
			for _, v := range findings {
				finding, _ := obj(v)
				req := httptest.NewRequest("GET", "/v1/jobs/test/dual-evidence?change="+url.QueryEscape(str(finding["finding_id"])), nil)
				rec := httptest.NewRecorder()
				if e := s.serveDualEvidence(rec, req, base, p, analysis); e != nil {
					t.Fatalf("finite rule HTTP query: %v", e)
				}
				if rec.Code != 200 {
					t.Fatalf("finite query status %d", rec.Code)
				}
				var reply map[string]any
				if e := json.Unmarshal(rec.Body.Bytes(), &reply); e != nil {
					t.Fatal(e)
				}
				if _, historical := reply["compatibility"]; historical {
					t.Fatal("new version marked historical")
				}
				selection, _ := obj(reply["selection"])
				got, _ := obj(selection["rule_finding"])
				originals, _ := arr(reply["verified_original_evidence"])
				if got["finding_id"] != finding["finding_id"] || len(originals) == 0 {
					t.Fatal("finite HTTP query omitted finding or original evidence")
				}
				if real && reply["source_provenance"] == nil {
					t.Fatal("real finite query omitted declaration")
				}
			}
			originals, fields, e := s.dualEvidence(base, p, analysis, analysis)
			if e != nil {
				t.Fatal(e)
			}
			seen := map[string]bool{}
			for _, v := range originals {
				row, _ := obj(v)
				r, _ := obj(row["source_ref"])
				if r["frame_number"] != nil {
					seen[str(r["file_sha256"])] = true
				}
			}
			if len(seen) != 2 || len(fields) == 0 {
				t.Fatal("evidence lost secondary capture or network fields")
			}
			other := filepath.Join(root, base, "dual/sources/network-001.pcap")
			if e = os.WriteFile(other, []byte("tampered"), 0600); e != nil {
				t.Fatal(e)
			}
			if _, _, e = s.dualEvidence(base, p, analysis, analysis); e == nil {
				t.Fatal("changed secondary capture accepted")
			}
		})
	}
}

func shaBytes(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
