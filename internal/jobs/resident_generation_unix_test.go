//go:build linux || darwin

package jobs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func composeFixture() ResidentExecution {
	return ResidentExecution{Version: "resident-registration-1", Backend: "compose-pid1-v1", DeploymentID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), SupervisorID: "worker-01", ContainerID: "pid1://" + strings.Repeat("b", 32)}
}
func lockedGeneration(t *testing.T, root string, p ResidentExecution) *os.File {
	t.Helper()
	directory := filepath.Join(root, "resident-generations")
	if e := os.MkdirAll(directory, 0700); e != nil {
		t.Fatal(e)
	}
	record := composeGeneration{Version: "resident-compose-generation-1", Deployment: p.DeploymentID, Generation: p.Generation, Supervisor: p.SupervisorID, PID: 1}
	raw, _ := json.Marshal(record)
	f, e := os.OpenFile(filepath.Join(directory, p.Generation+".lock"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.Close() })
	if _, e = f.Write(raw); e != nil {
		t.Fatal(e)
	}
	if e = f.Sync(); e != nil {
		t.Fatal(e)
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "resident-current.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	return f
}
func TestComposeIdentityRegistrationAndReplacementFencing(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	os.Chmod(root, 0700)
	p := composeFixture()
	if !validResidentIdentity(p) || !residentLocation("resident-compose:"+p.DeploymentID) {
		t.Fatal("compose identity rejected")
	}
	old := lockedGeneration(t, root, p)
	if e := verifyComposeRegistration(root, p); e != nil {
		t.Fatal(e)
	}
	if e := verifyComposeTermination(root, p); e == nil {
		t.Fatal("running old PID1 accepted as terminated")
	}
	if e := old.Close(); e != nil {
		t.Fatal(e)
	}
	if e := verifyComposeRegistration(root, p); e == nil {
		t.Fatal("inactive generation registered")
	}
	if e := verifyComposeTermination(root, p); e == nil {
		t.Fatal("unlock before replacement PID1 accepted")
	}
	replacement := p
	replacement.Generation = strings.Repeat("c", 32)
	replacement.ContainerID = "pid1://" + replacement.Generation
	active := lockedGeneration(t, root, replacement)
	if e := verifyComposeTermination(root, p); e != nil {
		t.Fatal(e)
	}
	if e := active.Close(); e != nil {
		t.Fatal(e)
	}
	if e := verifyComposeTermination(root, p); e == nil {
		t.Fatal("inactive replacement accepted")
	}
}
func TestComposeGenerationFilesFailClosed(t *testing.T) {
	for _, mutate := range []func(string, ResidentExecution){
		func(root string, p ResidentExecution) {
			os.Remove(filepath.Join(root, "resident-generations", p.Generation+".lock"))
		},
		func(root string, p ResidentExecution) {
			os.Chmod(filepath.Join(root, "resident-generations", p.Generation+".lock"), 0666)
		},
		func(root string, p ResidentExecution) {
			os.WriteFile(filepath.Join(root, "resident-current.json"), []byte(`{}`), 0600)
		},
		func(root string, p ResidentExecution) { os.Chmod(filepath.Join(root, "resident-generations"), 0755) },
		func(root string, p ResidentExecution) {
			path := filepath.Join(root, "resident-generations", p.Generation+".lock")
			os.Remove(path)
			os.Symlink(filepath.Join(root, "resident-current.json"), path)
		},
	} {
		root := t.TempDir()
		root, _ = filepath.EvalSymlinks(root)
		os.Chmod(root, 0700)
		p := composeFixture()
		lockedGeneration(t, root, p)
		mutate(root, p)
		if verifyComposeRegistration(root, p) == nil {
			t.Fatal("unsafe generation file accepted")
		}
	}
	p := composeFixture()
	p.PodUID = "0c3a6291-1ec0-4550-9220-62c135c8cedc"
	if validResidentIdentity(p) {
		t.Fatal("compose accepted fake Kubernetes identity")
	}
	p = composeFixture()
	if validResidentLocation(p, "resident-compose:"+strings.Repeat("f", 32)) {
		t.Fatal("deployment location mismatch")
	}
}
