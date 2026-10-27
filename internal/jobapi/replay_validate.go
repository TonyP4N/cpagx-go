package jobapi

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type replayVerified struct {
	Profile, Core, Analysis, Graph, Replay map[string]any
	Events                                 []any
	Snapshots, Revisions, Arrivals         []map[string]any
	Originals                              replayOriginals
}

func (s *Server) readReplayLines(base, name string, max int) ([]map[string]any, error) {
	path, e := s.file(base + name)
	if e != nil {
		return nil, e
	}
	raw, e := os.ReadFile(path)
	if e != nil || len(raw) > 16<<20 {
		return nil, errors.New("replay JSONL missing or oversized")
	}
	rows := []map[string]any{}
	if len(raw) == 0 {
		return rows, nil
	}
	if raw[len(raw)-1] != '\n' {
		return nil, errors.New("truncated replay JSONL")
	}
	for _, line := range bytes.Split(raw[:len(raw)-1], []byte{'\n'}) {
		if len(rows) >= max {
			return nil, errors.New("replay JSONL record limit")
		}
		value, e := parseValue(line)
		if e != nil {
			return nil, e
		}
		row, ok := obj(value)
		if !ok {
			return nil, errors.New("replay JSONL object required")
		}
		canonical, e := pythonCanonical(row)
		if e != nil || !bytes.Equal(canonical, line) {
			return nil, errors.New("noncanonical replay JSONL")
		}
		rows = append(rows, row)
	}
	return rows, nil
}
func (s *Server) replayInventory(base string, p Payload) error {
	root, e := s.file(strings.TrimSuffix(base, "/"))
	if e != nil {
		return e
	}
	expected := map[string]bool{}
	for _, name := range replayArtifactNamesFor(p) {
		expected[name] = true
	}
	found := map[string]bool{}
	total := int64(0)
	e = filepath.WalkDir(root, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if path == root {
			return nil
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("replay symlink forbidden")
		}
		if entry.IsDir() {
			if rel != "sources" {
				return errors.New("unknown replay directory")
			}
			return nil
		}
		info, e := entry.Info()
		if e != nil || !info.Mode().IsRegular() {
			return errors.New("nonregular replay artifact")
		}
		if !expected[rel] && rel != "manifest.json" && !dualAnchor.MatchString(rel) {
			return errors.New("unknown replay artifact")
		}
		if expected[rel] {
			total += info.Size()
		}
		if total > 16<<20 {
			return errors.New("replay output exceeds 16MiB")
		}
		found[rel] = true
		return nil
	})
	if e != nil {
		return e
	}
	anchors := 0
	for name := range found {
		if dualAnchor.MatchString(name) {
			anchors++
		}
	}
	if anchors > 1 || (anchors > 0 && !found["manifest.json"]) {
		return errors.New("invalid replay publication anchors")
	}
	for name := range expected {
		if !found[name] {
			return fmt.Errorf("missing replay artifact: %s", name)
		}
	}
	return nil
}
func (s *Server) validateReplay(base string, p Payload, wrapper Manifest, coreRaw []byte) (*replayVerified, error) {
	fail := func(message string) (*replayVerified, error) { return nil, errors.New(message) }
	if e := s.replayInventory(base, p); e != nil {
		return nil, e
	}
	if e := replaySchema("ReplayRunManifest", mustParse(coreRaw)); e != nil {
		return nil, e
	}
	value, e := parseValue(coreRaw)
	if e != nil {
		return nil, e
	}
	core, _ := obj(value)
	parts := strings.Split(strings.Trim(base, "/"), "/")
	attempt, _ := intValue(core["attempt_id"])
	if len(parts) != 3 || parts[0] != "jobs" || core["run_id"] != parts[1] || parts[2] != fmt.Sprintf("attempt-%d", attempt) || attempt < 1 || core["replay_version"] != p.ReplayVersion || p.ReplayVersion != ReplayVersion {
		return fail("replay run/attempt/version mismatch")
	}
	profileValue, e := s.readDualJSON(base, "sources/profile.json")
	if e != nil {
		return nil, e
	}
	profile, _ := obj(profileValue)
	if e = validateReplayProfile(profile, p.ReplayVersion); e != nil {
		return nil, e
	}
	fp, e := digestValue(profile)
	if e != nil || fp != p.Fingerprint || core["config_fingerprint"] != fp {
		return fail("replay complete profile fingerprint mismatch")
	}
	if _, e = s.check(Ref{base + "sources/profile.json", p.Profile.SHA}); e != nil {
		return nil, e
	}
	semantic := replaySemanticProfile(profile)
	semanticFP, e := digestValue(semantic)
	if e != nil || core["semantic_config_fingerprint"] != semanticFP {
		return fail("replay semantic profile fingerprint mismatch")
	}
	if core["synthetic"] != profile["synthetic"] {
		return fail("replay source category mismatch")
	}
	expectedEntries := map[string]bool{}
	for _, name := range replayArtifactNamesFor(p) {
		if name != "run_manifest.json" {
			expectedEntries[name] = true
		}
	}
	entries, ok := arr(core["artifacts"])
	if !ok || len(entries) != len(expectedEntries) {
		return fail("replay core artifact inventory mismatch")
	}
	var totalBytes int64
	for _, v := range entries {
		entry, ok := obj(v)
		name := str(entry["path"])
		if !ok || !expectedEntries[name] {
			return fail("replay core artifact name mismatch")
		}
		delete(expectedEntries, name)
		size, ok := intValue(entry["size_bytes"])
		n, e := s.check(Ref{base + name, str(entry["sha256"])})
		if !ok || e != nil || n != int64(size) {
			return fail("replay core artifact hash/size mismatch")
		}
		totalBytes += n
	}
	parametersForLimit, _ := obj(profile["replay"])
	configuredLimit, ok := intValue(parametersForLimit["max_output_bytes"])
	if !ok || totalBytes+int64(len(coreRaw)) > int64(configuredLimit) {
		return fail("replay configured output limit exceeded")
	}
	refs, _ := p.networkRefs()
	sourceRows := []any{}
	datasetValue, e := s.readDualJSON(base, "dataset.json")
	if e != nil {
		return nil, e
	}
	if e = replaySchema("DatasetManifest", datasetValue); e != nil {
		return nil, e
	}
	dataset, _ := obj(datasetValue)
	files, _ := arr(dataset["files"])
	if len(files) != len(refs)+1 || dataset["synthetic"] != profile["synthetic"] {
		return fail("replay dataset source set mismatch")
	}
	for i, ref := range append(refs, p.Process) {
		name := networkSourceName(i)
		kind := "network"
		if i == len(refs) {
			name = "sources/process.csv"
			kind = "process"
		}
		size, e := s.check(Ref{base + name, ref.SHA})
		if e != nil {
			return nil, e
		}
		originalSize, e := s.check(ref)
		if e != nil || originalSize != size {
			return fail("replay original source changed")
		}
		f, _ := obj(files[i])
		n, ok := intValue(f["size_bytes"])
		if !ok || int64(n) != size || f["sha256"] != ref.SHA || f["kind"] != kind || f["name"] != filepath.Base(name) {
			return fail("replay dataset original binding mismatch")
		}
		sourceRows = append(sourceRows, map[string]any{"kind": kind, "sha256": ref.SHA, "size_bytes": f["size_bytes"]})
	}
	inputFP, e := digestValue(sourceRows)
	if e != nil || core["input_fingerprint"] != inputFP || dataset["dataset_id"] != "replay-dataset-"+inputFP {
		return fail("replay complete input fingerprint mismatch")
	}
	if profile["synthetic"] == false {
		provenance, _ := obj(profile["source_provenance"])
		for _, key := range []string{"source", "release", "collection_range", "timezone_basis", "authorization_ref"} {
			if !sameJSON(dataset[key], provenance[key]) {
				return fail("replay dataset provenance mismatch")
			}
		}
	}
	originals, e := s.replayOriginals(base, p, profile)
	if e != nil {
		return nil, e
	}
	snapshots, e := s.readReplayLines(base, "snapshots.jsonl", 4096)
	if e != nil {
		return nil, e
	}
	revisions, e := s.readReplayLines(base, "revisions.jsonl", 8192)
	if e != nil {
		return nil, e
	}
	arrivals, e := s.readReplayLines(base, "arrivals.jsonl", 22001)
	if e != nil {
		return nil, e
	}
	if len(snapshots) == 0 {
		return fail("replay has no snapshots")
	}
	parameters, _ := obj(profile["replay"])
	maxSnapshots, _ := intValue(parameters["max_snapshots"])
	maxRevisions, _ := intValue(parameters["max_revisions"])
	if len(snapshots) > maxSnapshots || len(revisions) > maxRevisions {
		return fail("replay configured history limit exceeded")
	}
	sequence, _ := arr(parameters["sequence"])
	firstSeen := map[string]int{}
	lastArrival := 0
	var lastTime time.Time
	for _, row := range arrivals {
		seq, ok := intValue(row["arrival_seq"])
		at, e := time.Parse(time.RFC3339Nano, str(row["available_at"]))
		if !ok || seq <= lastArrival || seq > len(sequence)+1 || e != nil || (!lastTime.IsZero() && at.Before(lastTime)) {
			return fail("replay arrival ordering invalid")
		}
		if seq <= len(sequence) {
			step, _ := obj(sequence[seq-1])
			if step["available_at"] != row["available_at"] {
				a, e1 := time.Parse(time.RFC3339Nano, str(step["available_at"]))
				if e1 != nil || !a.Equal(at) {
					return fail("replay arrival schedule differs")
				}
			}
		} else if parameters["finish_at"] != row["available_at"] {
			a, e1 := time.Parse(time.RFC3339Nano, str(parameters["finish_at"]))
			if e1 != nil || !a.Equal(at) {
				return fail("replay final arrival time differs")
			}
		}
		all, e := replayRefs(row["evidence_refs"])
		if e != nil {
			return nil, e
		}
		for _, v := range all {
			ref, _ := obj(v)
			r, e := originals.resolve(ref)
			if e != nil {
				return nil, e
			}
			key := replayRecordKey(r.Slot, r.Number) + ":" + bytesSHA(r.Record)
			if _, exists := firstSeen[key]; !exists {
				firstSeen[key] = seq
			}
		}
		lastArrival = seq
		lastTime = at
	}
	tool, _ := obj(core["tool_versions"])
	coreVersion := str(tool["core"])
	previous := map[string]any(nil)
	revisionIndex := 0
	var lastSnapshotTime time.Time
	for i, snapshot := range snapshots {
		n, nok := intValue(snapshot["snapshot_number"])
		arrivalSeq, aok := intValue(snapshot["arrival_seq"])
		rn, rok := intValue(snapshot["revision_number"])
		at, e := time.Parse(time.RFC3339Nano, str(snapshot["available_at"]))
		if !nok || n != i || !aok || arrivalSeq < 0 || arrivalSeq > len(sequence)+1 || !rok || rn < 0 || e != nil || (!lastSnapshotTime.IsZero() && at.Before(lastSnapshotTime)) || snapshot["schema_version"] != "1.0.0" || snapshot["synthetic"] != profile["synthetic"] || snapshot["replay_version"] != ReplayVersion || snapshot["config_fingerprint"] != semanticFP || snapshot["semantic_config_fingerprint"] != semanticFP || snapshot["config_version"] != profile["config_version"] {
			return fail("replay snapshot identity/config/order mismatch")
		}
		analysis, ok := obj(snapshot["analysis"])
		if !ok || analysis["config_fingerprint"] != semanticFP || analysis["semantic_config_fingerprint"] != semanticFP {
			return fail("replay snapshot analysis fingerprint mismatch")
		}
		stateFP, e := digestValue(analysis)
		if e != nil || snapshot["state_fingerprint"] != stateFP {
			return fail("replay snapshot state fingerprint mismatch")
		}
		identity, _ := obj(normalizedJSON(snapshot))
		delete(identity, "snapshot_id")
		delete(identity, "graph")
		delete(identity, "events")
		snapshotFP, e := digestValue(identity)
		if e != nil || snapshot["snapshot_id"] != "snapshot-"+snapshotFP {
			return fail("replay snapshot immutable identity mismatch")
		}
		all, e := replayRefs(analysis)
		if e != nil {
			return nil, e
		}
		for _, v := range all {
			ref, _ := obj(v)
			r, e := originals.resolve(ref)
			if e != nil {
				return nil, e
			}
			key := replayRecordKey(r.Slot, r.Number) + ":" + bytesSHA(r.Record)
			seq, arrived := firstSeen[key]
			if !arrived || seq > arrivalSeq {
				return fail("snapshot exposes a record before arrival")
			}
		}
		events, graph, e := replayProjection(analysis, profile, coreVersion)
		if e != nil {
			return nil, e
		}
		if !sameJSON(snapshot["events"], events) || !sameJSON(snapshot["graph"], graph) {
			return fail("replay snapshot event/graph/claim projection mismatch")
		}
		if e = verifyReplayFields(analysis, originals); e != nil {
			return nil, e
		}
		changed := previous != nil && snapshot["state_fingerprint"] != previous["state_fingerprint"]
		expectedRN := revisionIndex
		if changed {
			expectedRN++
			if revisionIndex >= len(revisions) {
				return fail("missing replay immutable revision")
			}
			revision := revisions[revisionIndex]
			if e = replaySchema("ReplayRevision", revision); e != nil {
				return nil, e
			}
			rid, _ := obj(normalizedJSON(revision))
			delete(rid, "revision_id")
			hash, e := digestValue(rid)
			if e != nil || revision["revision_id"] != "revision-"+hash || revision["revision_number"] != snapshot["revision_number"] || revision["old_snapshot_id"] != previous["snapshot_id"] || revision["new_snapshot_id"] != snapshot["snapshot_id"] || revision["old_state_fingerprint"] != previous["state_fingerprint"] || revision["new_state_fingerprint"] != snapshot["state_fingerprint"] || revision["config_fingerprint"] != semanticFP || revision["semantic_config_fingerprint"] != semanticFP || revision["config_version"] != profile["config_version"] || revision["synthetic"] != profile["synthetic"] || revision["rule_version"] != profile["rule_version"] || revision["available_at"] != snapshot["available_at"] || !sameJSON(revision["trigger"], snapshot["trigger"]) {
				return fail("replay revision immutable chain mismatch")
			}
			trigger, _ := obj(snapshot["trigger"])
			want, e := replayRefs([]any{trigger["evidence_refs"], analysis})
			if e != nil || !sameJSON(revision["evidence_refs"], want) {
				return fail("replay revision original evidence mismatch")
			}
			if old, exists := revision["old_snapshot_number"]; exists && old != previous["snapshot_number"] {
				return fail("replay old snapshot number mismatch")
			}
			if next, exists := revision["new_snapshot_number"]; exists && next != snapshot["snapshot_number"] {
				return fail("replay new snapshot number mismatch")
			}
			revisionIndex++
		}
		if rn != expectedRN {
			return fail("replay snapshot revision sequence mismatch")
		}
		previous = snapshot
		lastSnapshotTime = at
	}
	if revisionIndex != len(revisions) {
		return fail("unlinked replay revisions")
	}
	last := snapshots[len(snapshots)-1]
	analysisValue, e := s.readDualJSON(base, "analysis.json")
	if e != nil {
		return nil, e
	}
	analysis, _ := obj(analysisValue)
	graphValue, e := s.readDualJSON(base, "graph.json")
	if e != nil {
		return nil, e
	}
	graph, _ := obj(graphValue)
	eventsValue, e := s.readDualJSON(base, "events.json")
	if e != nil {
		return nil, e
	}
	events, _ := arr(eventsValue)
	quality, e := s.readDualJSON(base, "quality.json")
	if e != nil {
		return nil, e
	}
	if !sameJSON(analysis, last["analysis"]) || !sameJSON(graph, last["graph"]) || !sameJSON(events, last["events"]) || !sameJSON(quality, analysis["quality"]) {
		return fail("replay final standard projection mismatch")
	}
	state, _ := obj(analysis["replay"])
	if state["phase"] != "finished" {
		return fail("incomplete replay cannot be published")
	}
	replayValue, e := s.readDualJSON(base, "replay.json")
	if e != nil {
		return nil, e
	}
	replay, _ := obj(replayValue)
	snapshotCount, _ := intValue(replay["snapshot_count"])
	revisionCount, _ := intValue(replay["revision_count"])
	if replay["schema_version"] != "1.0.0" || replay["replay_version"] != ReplayVersion || replay["analysis_version"] != currentBoundedAnalysisVersion || replay["semantic_config_fingerprint"] != semanticFP || replay["synthetic"] != profile["synthetic"] || snapshotCount != len(snapshots) || revisionCount != len(revisions) || replay["final_snapshot_id"] != last["snapshot_id"] {
		return fail("replay terminal summary mismatch")
	}
	hashes, _ := obj(core["result_hashes"])
	eh, e := digestValue(events)
	if e != nil {
		return nil, e
	}
	gh, e := digestValue(graph)
	if e != nil {
		return nil, e
	}
	if hashes["events"] != eh || hashes["graph"] != gh {
		return fail("replay final semantic hash mismatch")
	}
	if !sameJSON(core["limitations"], analysis["limitations"]) {
		return fail("replay limitations differ from analysis")
	}
	if e = s.verifyReplayMetrics(base, profile, arrivals); e != nil {
		return nil, e
	}
	_ = wrapper
	return &replayVerified{Profile: profile, Core: core, Analysis: analysis, Graph: graph, Replay: replay, Events: events, Snapshots: snapshots, Revisions: revisions, Arrivals: arrivals, Originals: originals}, nil
}
func mustParse(raw []byte) any { value, _ := parseValue(raw); return value }
func verifyReplayFields(analysis map[string]any, originals replayOriginals) error {
	network, _ := arr(analysis["network"])
	for _, v := range network {
		row, _ := obj(v)
		obs, _ := obj(row["observation"])
		fields, _ := obj(obs["fields"])
		for _, v := range fields {
			field, _ := obj(v)
			slices, _ := arr(field["slices"])
			if len(slices) == 0 {
				return errors.New("missing replay protocol field slices")
			}
			for _, v := range slices {
				piece, _ := obj(v)
				ref, _ := obj(piece["source_ref"])
				r, e := originals.resolve(ref)
				if e != nil {
					return e
				}
				offset, ok := intValue(piece["frame_byte_offset"])
				length, valid := intValue(piece["length"])
				if !ok || !valid || !packetRange(offset, length, len(r.Frame)) {
					return errors.New("replay protocol field outside original frame")
				}
				raw := r.Frame[offset : offset+length]
				if fmt.Sprintf("%x", raw) != piece["hex"] || bytesSHA(raw) != piece["sha256"] {
					return errors.New("replay protocol field bytes mismatch")
				}
			}
		}
	}
	return nil
}

func (s *Server) verifyReplayMetrics(base string, profile map[string]any, arrivals []map[string]any) error {
	metricsValue, e := s.readDualJSON(base, "metrics.json")
	if e != nil {
		return e
	}
	metrics, _ := obj(metricsValue)
	if metrics["replay_version"] != ReplayVersion || metrics["unit"] != "seconds" || !sameJSON(metrics["arrival_samples"], normalizedJSON(arrivals)) {
		return errors.New("replay arrival metrics mismatch")
	}
	runtimeValue, e := s.readDualJSON(base, "runtime_metrics.json")
	if e != nil {
		return e
	}
	runtime, _ := obj(runtimeValue)
	parameters, _ := obj(profile["replay"])
	speed := 1.0
	if v, ok := number(parameters["speed"]); ok {
		speed = v
	}
	actualSpeed, ok := number(runtime["speed"])
	elapsed, valid := number(runtime["elapsed_seconds"])
	paced, yes := runtime["paced"].(bool)
	if runtime["clock"] != "monotonic_wall_seconds" || !ok || actualSpeed != speed || !valid || elapsed < 0 || !yes {
		return errors.New("replay runtime metrics contract mismatch")
	}
	sequence, _ := arr(parameters["sequence"])
	samples, _ := arr(runtime["samples"])
	if len(samples) != len(sequence) {
		return errors.New("replay runtime schedule count mismatch")
	}
	start, e := time.Parse(time.RFC3339Nano, str(parameters["simulation_start"]))
	if e != nil {
		return e
	}
	previous := 0.0
	for i, v := range samples {
		sample, _ := obj(v)
		step, _ := obj(sequence[i])
		seq, ok := intValue(sample["arrival_seq"])
		if !ok || seq != i+1 || sample["available_at"] != step["available_at"] {
			return errors.New("replay runtime arrival identity mismatch")
		}
		at, e := time.Parse(time.RFC3339Nano, str(step["available_at"]))
		if e != nil {
			return e
		}
		target := at.Sub(start).Seconds() / speed
		scheduled, aok := number(sample["scheduled_elapsed_seconds"])
		actual, bok := number(sample["actual_elapsed_seconds"])
		processing, cok := number(sample["processing_seconds"])
		if !aok || !bok || !cok || math.Abs(scheduled-target) > 1e-6 || processing < 0 || actual < previous || actual > elapsed || (paced && actual+1e-6 < target) {
			return errors.New("replay runtime samples inconsistent")
		}
		previous = actual
	}
	coreSamples, _ := arr(runtime["core_samples"])
	if len(coreSamples) == 0 {
		return errors.New("replay core runtime samples missing")
	}
	for _, v := range coreSamples {
		sample, _ := obj(v)
		wall, ok := number(sample["wall_seconds"])
		if !ok || wall < 0 {
			return errors.New("replay core runtime sample invalid")
		}
	}
	return nil
}
