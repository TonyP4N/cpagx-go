package jobs

import (
	"strings"
	"testing"
	"time"
)

func TestKubeExitBinding(t *testing.T) {
	job := "ea28a1ad-8246-4420-8993-ddcee4256df1"
	pod := "0c3a6291-1ec0-4550-9220-62c135c8cedc"
	c := Claim{ID: "run", Worker: "worker", Attempt: 2}
	zero := 0
	k := KubeTermination{Version: "kubernetes-termination-1", Run: c.ID, Worker: c.Worker, Attempt: c.Attempt, Namespace: "cpag", JobUID: job, PodUID: pod, Container: "containerd://" + strings.Repeat("1", 64), Finished: time.Now(), ExitCode: &zero}
	p := ExitProof{Scope: "kubernetes-job", Exited: true, Location: "kubernetes:" + pod, ContainerID: job, Kubernetes: &k}
	if !validKubeExit(c, p) {
		t.Fatal("rejected matching proof")
	}
	for _, change := range []func(*KubeTermination){func(k *KubeTermination) { k.Attempt-- }, func(k *KubeTermination) { k.JobUID = pod }, func(k *KubeTermination) { k.PodUID = "" }, func(k *KubeTermination) { k.Container = "containerd://missing" }, func(k *KubeTermination) { k.ExitCode = nil }} {
		bad := k
		change(&bad)
		p.Kubernetes = &bad
		if validKubeExit(c, p) {
			t.Fatal("accepted mismatched or incomplete proof")
		}
	}
}
