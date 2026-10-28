package jobapi

import (
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strconv"
)

func replayQueryInt(r *http.Request, name string, defaultValue, min, max int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return defaultValue, nil
	}
	n, e := strconv.Atoi(raw)
	if e != nil || n < min || n > max {
		return 0, errors.New("invalid replay " + name)
	}
	return n, nil
}
func replaySnapshot(data *replayVerified, n int) (map[string]any, error) {
	if n < 0 || n >= len(data.Snapshots) {
		return nil, errors.New("unknown replay snapshot")
	}
	row := data.Snapshots[n]
	actual, _ := intValue(row["snapshot_number"])
	if actual != n {
		return nil, errors.New("replay snapshot index mismatch")
	}
	return row, nil
}
func (s *Server) serveReplay(w http.ResponseWriter, r *http.Request, id, kind string) error {
	base, p, _, e := s.publishedDual(r, id)
	if e != nil {
		return e
	}
	if p.Kind != "dual-source-replay" {
		return errors.New("replay route requires replay task")
	}
	if p.HistoryFormat == ReplaySpoolFormat {
		return s.serveSpoolReplay(w, r, base, p, kind)
	}
	rawPath, e := s.file(base + "run_manifest.json")
	if e != nil {
		return e
	}
	raw, e := readFileBounded(rawPath, 65536)
	if e != nil {
		return e
	}
	data, e := s.validateReplay(base, p, Manifest{}, raw)
	if e != nil {
		return e
	}
	switch kind {
	case "replay-revisions":
		after, e := replayQueryInt(r, "after", 0, 0, 8192)
		if e != nil {
			return e
		}
		limit, e := replayQueryInt(r, "limit", 100, 1, 8192)
		if e != nil {
			return e
		}
		if after > len(data.Revisions) {
			after = len(data.Revisions)
		}
		end := after + limit
		if end > len(data.Revisions) {
			end = len(data.Revisions)
		}
		reply(w, 200, map[string]any{"mode": "dual_source_replay", "replay_version": ReplayVersion, "revisions": data.Revisions[after:end], "total": len(data.Revisions)})
		return nil
	case "replay-result":
		analysis, graph, events := data.Analysis, data.Graph, data.Events
		var snapshotNumber any
		if r.URL.Query().Has("revision") {
			n, e := replayQueryInt(r, "revision", -1, 0, 4095)
			if e != nil {
				return e
			}
			snapshot, e := replaySnapshot(data, n)
			if e != nil {
				return e
			}
			analysis, _ = obj(snapshot["analysis"])
			graph, _ = obj(snapshot["graph"])
			events, _ = arr(snapshot["events"])
			snapshotNumber = n
		}
		reply(w, 200, map[string]any{"mode": "dual_source_replay", "replay_version": ReplayVersion, "synthetic": analysis["synthetic"], "revision": snapshotNumber, "data": map[string]any{"analysis": analysis, "graph": graph, "events": events, "quality": analysis["quality"], "replay": data.Replay}})
		return nil
	case "replay-snapshot", "replay-evidence":
		n, e := replayQueryInt(r, "revision", -1, 0, 4095)
		if e != nil {
			return e
		}
		snapshot, e := replaySnapshot(data, n)
		if e != nil {
			return e
		}
		if kind == "replay-snapshot" {
			reply(w, 200, snapshot)
			return nil
		}
		analysis, _ := obj(snapshot["analysis"])
		return s.serveReplayEvidence(w, r, data, snapshot, analysis, n)
	default:
		return errors.New("unknown replay projection")
	}
}
func (s *Server) serveReplayEvidence(w http.ResponseWriter, r *http.Request, data *replayVerified, snapshot, analysis map[string]any, n int) error {
	query := r.URL.Query()
	operation, change := query.Get("operation"), query.Get("change")
	triggerValues, present := query["trigger"]
	trigger := false
	if present {
		if len(triggerValues) != 1 || triggerValues[0] != "true" {
			return errors.New("replay trigger selector must be exactly true")
		}
		trigger = true
	}
	count := 0
	if operation != "" {
		count++
	}
	if change != "" {
		count++
	}
	if trigger {
		count++
	}
	if count != 1 {
		return errors.New("select exactly one replay operation, change or trigger")
	}
	selected := map[string]any{}
	if trigger {
		selected["trigger"] = snapshot["trigger"]
	} else if operation != "" {
		operations, _ := arr(analysis["operations"])
		if operation == "first" && len(operations) > 0 {
			first, _ := obj(operations[0])
			operation = str(first["operation_id"])
		}
		for _, v := range operations {
			op, _ := obj(v)
			if op["operation_id"] == operation {
				selected["operation"] = op
				break
			}
		}
		if selected["operation"] == nil {
			return errors.New("unknown replay operation")
		}
		candidates, _ := arr(analysis["candidates"])
		changes, _ := arr(analysis["changes"])
		chosen := []any{}
		linked := []any{}
		ids := map[string]bool{}
		for _, v := range candidates {
			c, _ := obj(v)
			if c["operation_id"] == operation {
				chosen = append(chosen, c)
				ids[str(c["change_id"])] = true
			}
		}
		for _, v := range changes {
			c, _ := obj(v)
			if ids[str(c["event_id"])] {
				linked = append(linked, c)
			}
		}
		selected["candidates"] = chosen
		selected["changes"] = linked
	} else {
		changes, _ := arr(analysis["changes"])
		if change == "first" && len(changes) > 0 {
			first, _ := obj(changes[0])
			change = str(first["event_id"])
		}
		for _, v := range changes {
			c, _ := obj(v)
			if c["event_id"] == change {
				selected["change"] = c
				break
			}
		}
		findings, _ := arr(analysis["rule_findings"])
		for _, v := range findings {
			f, _ := obj(v)
			if f["finding_id"] == change {
				selected["rule_finding"] = f
				break
			}
		}
		if len(selected) != 1 {
			return errors.New("unknown or ambiguous replay change")
		}
	}
	refs, e := replayEvidenceRefsAt(data, snapshot, selected)
	if e != nil {
		return e
	}
	originals := []any{}
	selectedFrames := map[string]bool{}
	for _, v := range refs {
		ref, _ := obj(v)
		original, e := data.Originals.originalValue(ref)
		if e != nil {
			return e
		}
		originals = append(originals, map[string]any{"source_ref": ref, "original": original})
		if ref["frame_number"] != nil {
			number, _ := intValue(ref["frame_number"])
			selectedFrames[replayRecordKey(str(ref["source_slot"]), number)] = true
		}
	}
	fields := []any{}
	network, _ := arr(analysis["network"])
	for _, v := range network {
		row, _ := obj(v)
		obs, _ := obj(row["observation"])
		refs, _ := arr(obs["source_refs"])
		include := false
		for _, v := range refs {
			ref, _ := obj(v)
			number, _ := intValue(ref["frame_number"])
			include = include || selectedFrames[replayRecordKey(str(ref["source_slot"]), number)]
		}
		if !include {
			continue
		}
		fieldMap, _ := obj(obs["fields"])
		named := map[string]any{}
		for name, v := range fieldMap {
			field, _ := obj(v)
			slices, _ := arr(field["slices"])
			resolved := []any{}
			for _, v := range slices {
				piece, _ := obj(v)
				ref, _ := obj(piece["source_ref"])
				original, e := data.Originals.resolve(ref)
				if e != nil {
					return e
				}
				offset, _ := intValue(piece["frame_byte_offset"])
				copied, _ := obj(normalizedJSON(piece))
				copied["absolute_byte_offset"] = original.Offset + offset
				resolved = append(resolved, map[string]any{"source_ref": ref, "raw_hex": hex.EncodeToString(original.Frame), "field": copied, "integrity": "arrived_record_sha256_verified"})
			}
			named[name] = resolved
		}
		event, _ := obj(row["event"])
		fields = append(fields, map[string]any{"event_id": event["event_id"], "fields": named})
	}
	reply(w, 200, map[string]any{"mode": "dual_source_replay", "replay_version": ReplayVersion, "synthetic": analysis["synthetic"], "revision": n, "snapshot_id": snapshot["snapshot_id"], "available_at": snapshot["available_at"], "selection": selected, "verified_original_evidence": originals, "verified_network_fields": fields, "quality": analysis["quality"], "config_fingerprint": analysis["config_fingerprint"], "limitations": analysis["limitations"]})
	return nil
}

func readFileBounded(path string, limit int64) ([]byte, error) {
	info, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("replay file limit")
	}
	return os.ReadFile(path)
}

func replayEvidenceRefsAt(data *replayVerified, snapshot, selected map[string]any) ([]any, error) {
	refs, e := replayRefs(selected)
	if e != nil {
		return nil, e
	}
	at, ok := intValue(snapshot["arrival_seq"])
	if !ok {
		return nil, errors.New("invalid replay evidence snapshot arrival")
	}
	arrived := map[string]bool{}
	for _, row := range data.Arrivals {
		seq, valid := intValue(row["arrival_seq"])
		if !valid || seq > at {
			continue
		}
		originalRefs, e := replayRefs(row["evidence_refs"])
		if e != nil {
			return nil, e
		}
		for _, v := range originalRefs {
			ref, _ := obj(v)
			r, e := data.Originals.resolve(ref)
			if e != nil {
				return nil, e
			}
			arrived[replayRecordKey(r.Slot, r.Number)+":"+bytesSHA(r.Record)] = true
		}
	}
	for _, v := range refs {
		ref, _ := obj(v)
		r, e := data.Originals.resolve(ref)
		if e != nil {
			return nil, e
		}
		if !arrived[replayRecordKey(r.Slot, r.Number)+":"+bytesSHA(r.Record)] {
			return nil, errors.New("replay evidence record has not arrived at snapshot")
		}
	}
	return refs, nil
}
