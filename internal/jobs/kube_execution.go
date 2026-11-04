package jobs

import (
	"regexp"
	"strings"
	"time"
)

// A namespace UID identifies a deployment even if a namespace of the same name is recreated.
var kubeUID = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

func kubeLocation(location string) bool {
	uid, ok := strings.CutPrefix(location, "kubernetes:")
	return ok && kubeUID.MatchString(uid)
}

type KubeTermination struct {
	Version   string    `json:"version"`
	Run       string    `json:"run_id"`
	Attempt   int       `json:"attempt"`
	Worker    string    `json:"worker"`
	Namespace string    `json:"namespace"`
	JobUID    string    `json:"job_uid"`
	PodUID    string    `json:"pod_uid"`
	Container string    `json:"container_id"`
	Finished  time.Time `json:"finished_at"`
	ExitCode  *int      `json:"exit_code"`
}

func validKubeExit(c Claim, p ExitProof) bool {
	k := p.Kubernetes
	if k == nil || !kubeLocation(p.Location) || p.Scope != "kubernetes-job" || !p.Exited || k.Version != "kubernetes-termination-1" || k.Run != c.ID || k.Attempt != c.Attempt || k.Worker != c.Worker || k.Namespace != "cpag" || k.JobUID != p.ContainerID || !kubeUID.MatchString(k.JobUID) || !kubeUID.MatchString(k.PodUID) || k.JobUID == k.PodUID || k.Finished.IsZero() || k.ExitCode == nil {
		return false
	}
	raw, ok := strings.CutPrefix(k.Container, "containerd://")
	return ok && digest.MatchString(raw)
}
