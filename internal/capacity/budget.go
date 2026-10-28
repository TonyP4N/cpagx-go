// Package capacity defines finite, opt-in execution budgets. It grants no
// capability to bypass parser, evidence, publication or authorization checks.
package capacity

import "fmt"

const Engineering = "engineering-capacity-1"
const DevelopmentS100 = "r19-dev-s100-1"

type Budget struct {
	Version                                                             string
	NetworkFiles, Frames, FrameBytes, ProcessRecords, ProcessColumns    int
	NetworkFileBytes, NetworkTotalBytes, ProcessBytes, ProfileBytes     int64
	Operations, Changes, Candidates, ArrivalSteps, Snapshots, Revisions int
	OutputBytes                                                         int64
}

// Resolve returns values, never a mutable shared preset. Empty means the
// historical profile with its original limits; unknown versions fail closed.
func Resolve(version string) (Budget, error) {
	b := Budget{Version: version, NetworkFiles: 4, NetworkFileBytes: 16 << 20, NetworkTotalBytes: 16 << 20,
		Frames: 10000, FrameBytes: 262144, ProcessBytes: 2 << 20, ProcessRecords: 1000, ProcessColumns: 16,
		ProfileBytes: 65536, Operations: 100, Changes: 1000, Candidates: 10000, ArrivalSteps: 22000,
		Snapshots: 4096, Revisions: 8192, OutputBytes: 16 << 20}
	switch version {
	case "":
		return b, nil
	case Engineering:
		b.NetworkFileBytes = 64 << 20
		b.NetworkTotalBytes = 128 << 20
		b.Frames = 100000
		b.ProcessBytes = 8 << 20
		b.ProcessRecords = 10000
		b.ProfileBytes = 8 << 20
		b.Operations = 10000
		b.Changes = 10000
		b.Candidates = 100000
		b.ArrivalSteps = 40000
		b.Snapshots = 45000
		b.Revisions = 90000
		b.OutputBytes = 1 << 30
		return b, nil
	default:
		return Budget{}, fmt.Errorf("unsupported capacity profile %q", version)
	}
}

func FromDocument(doc map[string]any) (Budget, error) {
	value, exists := doc["capacity_profile"]
	if !exists {
		return Resolve("")
	}
	version, ok := value.(string)
	if !ok || version == "" {
		return Budget{}, fmt.Errorf("explicit capacity profile must be a supported nonempty string")
	}
	if doc["analysis_mode"] != "bounded-real-capable-v1" {
		return Budget{}, fmt.Errorf("capacity profile requires explicit bounded analysis mode")
	}
	return Resolve(version)
}

func (b Budget) CheckInputSizes(networks []int64, process, profile int64) error {
	if len(networks) < 1 || len(networks) > b.NetworkFiles {
		return fmt.Errorf("network file count budget exceeded")
	}
	var total int64
	for _, size := range networks {
		if size < 0 || size > b.NetworkFileBytes {
			return fmt.Errorf("network file byte budget exceeded")
		}
		total += size
		if total > b.NetworkTotalBytes {
			return fmt.Errorf("aggregate network byte budget exceeded")
		}
	}
	if process < 0 || process > b.ProcessBytes || profile < 0 || profile > b.ProfileBytes {
		return fmt.Errorf("process or profile byte budget exceeded")
	}
	return nil
}

// ArtifactBytes is an operator resource policy, separate from input semantics.
// The development policy allows comparing the same old profile and input bytes.
func ArtifactBytes(resourceProfile string) (int64, error) {
	switch resourceProfile {
	case "":
		return 64 << 20, nil // unchanged old per-file service guard
	case DevelopmentS100:
		return 512 << 20, nil
	case Engineering:
		return 1 << 30, nil
	default:
		return 0, fmt.Errorf("unsupported resource profile %q", resourceProfile)
	}
}
