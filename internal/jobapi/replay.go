package jobapi

import (
	"errors"
	"fmt"
	"time"
)

const ReplayVersion = "dual-source-replay-1"

func dualFamily(kind string) bool { return kind == "dual-source" || kind == "dual-source-replay" }
func validateReplayProfile(value any, version string) error {
	doc, ok := obj(value)
	if !ok {
		return errors.New("replay profile object required")
	}
	replay, ok := obj(doc["replay"])
	if !ok || version != ReplayVersion || replay["version"] != version || doc["analysis_mode"] != "bounded-real-capable-v1" {
		return errors.New("explicit supported replay version and bounded profile required")
	}
	if e := replaySchema("ReplayProfile", replay); e != nil {
		return e
	}
	sequence, ok := arr(replay["sequence"])
	if !ok || len(sequence) == 0 || len(sequence) > 22000 {
		return errors.New("explicit bounded replay arrival sequence required")
	}
	at, e := time.Parse(time.RFC3339Nano, str(replay["simulation_start"]))
	if e != nil {
		return e
	}
	for _, v := range sequence {
		step, ok := obj(v)
		if !ok {
			return errors.New("replay arrival object required")
		}
		next, e := time.Parse(time.RFC3339Nano, str(step["available_at"]))
		if e != nil || next.Before(at) {
			return errors.New("replay arrival clock must be explicit and monotonic")
		}
		at = next
		kind := str(step["kind"])
		switch kind {
		case "advance":
			if len(step) != 2 {
				return errors.New("invalid replay clock advance")
			}
		case "source_eof":
			if len(step) != 3 || step["source_slot"] == nil {
				return errors.New("invalid replay source EOF")
			}
		case "", "record":
			number, ok := intValue(step["record_number"])
			if !ok || number < 1 || step["source_slot"] == nil {
				return errors.New("invalid replay source ordinal")
			}
			for key := range step {
				if key != "kind" && key != "source_slot" && key != "record_number" && key != "record_sha256" && key != "available_at" {
					return errors.New("unknown replay arrival field")
				}
			}
			if hash, present := step["record_sha256"]; present && !shaPattern.MatchString(str(hash)) {
				return errors.New("invalid replay declared record hash")
			}
		default:
			return errors.New("unsupported replay arrival action")
		}
	}
	finish, e := time.Parse(time.RFC3339Nano, str(replay["finish_at"]))
	if e != nil || finish.Before(at) {
		return errors.New("explicit replay finish cannot precede arrival sequence")
	}
	return nil
}
func validateReplaySourceSlots(value any, count int) error {
	doc, _ := obj(value)
	replay, _ := obj(doc["replay"])
	sequence, _ := arr(replay["sequence"])
	for _, v := range sequence {
		step, _ := obj(v)
		if step["kind"] == "advance" {
			continue
		}
		slot := str(step["source_slot"])
		valid := slot == "process"
		for i := 0; i < count; i++ {
			valid = valid || slot == fmt.Sprintf("network-%d", i)
		}
		if !valid {
			return errors.New("replay source slot does not belong to bound input set")
		}
	}
	return nil
}
func replayArtifactNamesFor(p Payload) []string {
	names := []string{"dataset.json", "events.json", "graph.json", "quality.json", "analysis.json", "run_manifest.json", "replay.json", "snapshots.jsonl", "revisions.jsonl", "arrivals.jsonl", "metrics.json", "runtime_metrics.json", "sources/process.csv", "sources/profile.json"}
	refs, _ := p.networkRefs()
	for i := range refs {
		names = append(names, networkSourceName(i))
	}
	return names
}
func validReplayArtifactPath(path string) bool {
	p := Payload{Kind: "dual-source-replay"}
	names := replayArtifactNamesFor(p)
	for i := 1; i < 4; i++ {
		names = append(names, networkSourceName(i))
	}
	for _, name := range names {
		if path == name {
			return true
		}
	}
	return false
}
func replayBase(id string, attempt int) string {
	return fmt.Sprintf("jobs/%s/attempt-%d/", id, attempt)
}
