package jobapi

import (
	"errors"
	"fmt"
	"github.com/TonyP4N/cpagx-go/internal/capacity"
	"time"
)

const ReplayVersion = "dual-source-replay-1"
const ReplaySpoolFormat = "replay-history-checkpoint-delta-2"

func replayProfileSchema(doc map[string]any) (string, string, error) {
	replay, _ := obj(doc["replay"])
	if storage, exists := doc["storage_format"]; exists {
		if storage != capacity.SharedFormat && storage != capacity.CoreSharedFormat {
			return "", "", errors.New("unsupported explicit storage format")
		}
		if _, err := capacity.FromDocument(doc); err != nil {
			return "", "", err
		}
		format := ""
		if _, exists := doc["replay"]; exists {
			format = str(replay["history_format"])
			if format != storage {
				return "", "", errors.New("shared replay history binding missing")
			}
		}
		if storage == capacity.CoreSharedFormat {
			return "DualCompactProfile", format, nil
		}
		return "DualSharedProfile", format, nil
	}
	value, exists := replay["history_format"]
	if !exists {
		return "DualSourceProfile", "", nil
	}
	format, ok := value.(string)
	if !ok || format != ReplaySpoolFormat {
		return "", "", errors.New("unsupported explicit replay history format")
	}
	return "DualSpoolProfile", format, nil
}

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
	_, format, formatErr := replayProfileSchema(doc)
	if formatErr != nil {
		return formatErr
	}
	schemaName := "ReplayProfile"
	if format == ReplaySpoolFormat {
		schemaName = "ReplaySpoolProfile"
	} else if format == capacity.CoreSharedFormat {
		schemaName = "ReplayCompactProfile"
	} else if format == capacity.SharedFormat {
		schemaName = "ReplaySharedProfile"
	}
	if e := replaySchema(schemaName, replay); e != nil {
		return e
	}
	sequence, ok := arr(replay["sequence"])
	budget, e := capacity.FromDocument(doc)
	if e != nil {
		return e
	}
	if !ok || len(sequence) == 0 || len(sequence) > budget.ArrivalSteps {
		return errors.New("explicit bounded replay arrival sequence required")
	}
	if format == ReplaySpoolFormat || format == capacity.SharedFormat || format == capacity.CoreSharedFormat {
		bufferMax := 11000
		if budget.Version != "" {
			bufferMax = budget.ArrivalSteps
		}
		for key, maximum := range map[string]int{"max_buffer_records": bufferMax, "max_snapshots": budget.Snapshots, "max_revisions": budget.Revisions, "max_output_bytes": int(budget.OutputBytes)} {
			n, valid := intValue(replay[key])
			if !valid || n < 1 || n > maximum {
				return fmt.Errorf("replay %s exceeds frozen capacity budget", key)
			}
		}
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
	if IsCompactPayload(p) {
		return compactArtifactNames(p)
	}
	names := []string{"dataset.json", "events.json", "graph.json", "quality.json", "analysis.json", "run_manifest.json", "replay.json", "snapshots.jsonl", "revisions.jsonl", "arrivals.jsonl", "metrics.json", "runtime_metrics.json", "sources/process.csv", "sources/profile.json"}
	if p.HistoryFormat == ReplaySpoolFormat {
		names = []string{"dataset.json", "events.json", "graph.json", "quality.json", "analysis.json", "run_manifest.json", "replay.json", "history/manifest.json", "history/history.sqlite3", "arrivals.jsonl", "metrics.json", "runtime_metrics.json", "sources/process.csv", "sources/profile.json"}
	}
	refs, _ := p.networkRefs()
	for i := range refs {
		names = append(names, networkSourceName(i))
	}
	return names
}

func validPayloadArtifactPath(p Payload, path string) bool {
	if IsCompactPayload(p) {
		for _, name := range compactArtifactNames(p) {
			if name == path {
				return true
			}
		}
		return false
	}
	if p.Kind == "dual-source-replay" && p.HistoryFormat == ReplaySpoolFormat {
		for _, name := range replayArtifactNamesFor(p) {
			if name == path {
				return true
			}
		}
		return false
	}
	return validArtifactPath(path, p.Kind)
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
