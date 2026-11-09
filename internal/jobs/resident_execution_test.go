package jobs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func residentFixture() ResidentExecution {
	return ResidentExecution{Version: "resident-registration-1", Namespace: "cpag", PodName: "worker-0", PodUID: "0c3a6291-1ec0-4550-9220-62c135c8cedc", ContainerName: "worker", ContainerID: "containerd://" + strings.Repeat("a", 64)}
}
func TestResidentProofFencesIdentityAndRequiresGuardianGroupExit(t *testing.T) {
	c := Claim{ID: "run", Attempt: 1, Worker: "worker", Token: "token"}
	k := residentFixture()
	k.Version = "resident-guardian-1"
	k.ChildPID = 3
	k.GuardianPID = 2
	k.GroupExited = true
	zero := 0
	k.ReturnCode = &zero
	p := ExitProof{ID: c.ID, Attempt: c.Attempt, Worker: c.Worker, Token: c.Token, Location: "resident:" + k.PodUID, ContainerID: k.ContainerID, Scope: "resident-process-group", Exited: true, Resident: &k}
	if !validResidentExit(c, p, false) {
		t.Fatal("valid proof rejected")
	}
	for _, change := range []func(*ExitProof){func(p *ExitProof) { p.Token = "other" }, func(p *ExitProof) { p.ContainerID = "other" }, func(p *ExitProof) { p.Resident.GroupExited = false }, func(p *ExitProof) { p.Resident.ChildPID = 0 }, func(p *ExitProof) { p.Resident.ReturnCode = nil }, func(p *ExitProof) { p.Resident.Version = "resident-container-terminated-1" }} {
		copy := p
		identity := *p.Resident
		copy.Resident = &identity
		change(&copy)
		if validResidentExit(c, copy, false) {
			t.Fatal("accepted invalid guardian proof")
		}
	}
}
func TestResidentRecoveryRequiresExactTerminatedContainer(t *testing.T) {
	registered := residentFixture()
	termination := map[string]any{"containerID": registered.ContainerID, "exitCode": 137, "finishedAt": time.Now().UTC().Format(time.RFC3339Nano)}
	pod := map[string]any{"metadata": map[string]any{"uid": registered.PodUID, "name": registered.PodName, "namespace": registered.Namespace}, "status": map[string]any{"containerStatuses": []any{map[string]any{"name": registered.ContainerName, "state": map[string]any{"running": map[string]any{}}, "lastState": map[string]any{"terminated": termination}}}}}
	raw, _ := json.Marshal(pod)
	proof, err := terminatedResident(raw, registered)
	if err != nil || proof.Version != "resident-container-terminated-1" || *proof.ReturnCode != 137 {
		t.Fatal(proof, err)
	}
	for _, change := range []func(){func() { termination["containerID"] = "containerd://" + strings.Repeat("b", 64) }, func() { termination["finishedAt"] = "" }, func() { termination["exitCode"] = nil }} {
		saved := map[string]any{}
		for k, v := range termination {
			saved[k] = v
		}
		change()
		raw, _ = json.Marshal(pod)
		if _, err = terminatedResident(raw, registered); err == nil {
			t.Fatal("accepted uncertain termination")
		}
		for k, v := range saved {
			termination[k] = v
		}
	}
	pod["metadata"].(map[string]any)["uid"] = "ea28a1ad-8246-4420-8993-ddcee4256df1"
	raw, _ = json.Marshal(pod)
	if _, err = terminatedResident(raw, registered); err == nil {
		t.Fatal("replacement Pod accepted")
	}
}
func TestResidentLocation(t *testing.T) {
	if !residentLocation("resident:"+residentFixture().PodUID) || residentLocation("resident:cpag") || residentLocation("kubernetes:"+residentFixture().PodUID) {
		t.Fatal("location boundary")
	}
}
