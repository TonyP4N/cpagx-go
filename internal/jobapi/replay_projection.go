package jobapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TonyP4N/cpagx-go/internal/contracts"
	"math"
	"sort"
	"time"
)

func normalizedJSON(value any) any {
	raw, _ := json.Marshal(value)
	out, _ := parseValue(raw)
	return out
}
func replaySemanticProfile(profile map[string]any) map[string]any {
	copy, _ := obj(normalizedJSON(profile))
	replay, _ := obj(copy["replay"])
	for _, key := range []string{"sequence", "finish_at", "speed", "realtime", "realtime_pacing", "history_format"} {
		delete(replay, key)
	}
	return copy
}
func replaySchema(name string, value any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	return contracts.Validate(dualSchemaDir(), name, raw)
}
func replayRefs(value any) ([]any, error) {
	refs := map[string]any{}
	var visit func(any) error
	visit = func(v any) error {
		switch x := v.(type) {
		case map[string]any:
			if _, present := x["file_sha256"]; present {
				return errors.New("full-file source reference forbidden in replay prefix")
			}
			if _, present := x["record_sha256"]; present {
				if e := replaySchema("ReplaySourceRef", x); e != nil {
					return e
				}
				key, e := pythonCanonical(x)
				if e != nil {
					return e
				}
				refs[string(key)] = x
				return nil
			}
			for _, v := range x {
				if e := visit(v); e != nil {
					return e
				}
			}
		case []any:
			for _, v := range x {
				if e := visit(v); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if e := visit(value); e != nil {
		return nil, e
	}
	keys := []string{}
	for key := range refs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := []any{}
	for _, key := range keys {
		out = append(out, refs[key])
	}
	return out, nil
}
func pythonUTC(value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	n, ok := number(value)
	if !ok || math.IsNaN(n) || math.IsInf(n, 0) {
		return nil, errors.New("invalid finite finding time")
	}
	at := time.UnixMicro(int64(math.Round(n * 1e6))).UTC()
	format := "2006-01-02T15:04:05Z"
	if at.Nanosecond() != 0 {
		format = "2006-01-02T15:04:05.000000Z"
	}
	return at.Format(format), nil
}

// Rebuild the standard graph and claims from the semantic analysis. Hashes alone
// cannot authorize a changed claim, edge target, or source evidence projection.
func replayProjection(analysis, profile map[string]any, coreVersion string) ([]any, map[string]any, error) {
	network, nok := arr(analysis["network"])
	process, pok := arr(analysis["process"])
	changes, cok := arr(analysis["changes"])
	candidates, aok := arr(analysis["candidates"])
	operations, ook := arr(analysis["operations"])
	if !nok || !pok || !cok || !aok || !ook {
		return nil, nil, errors.New("invalid replay analysis lists")
	}
	synthetic, ok := profile["synthetic"].(bool)
	if !ok || analysis["synthetic"] != synthetic || analysis["analysis_version"] != currentBoundedAnalysisVersion || analysis["replay_version"] != ReplayVersion {
		return nil, nil, errors.New("replay analysis category/version mismatch")
	}
	events := []any{}
	nodes := []any{}
	edges := []any{}
	claims := []any{}
	eventIDs := map[string]bool{}
	processByID := map[string]map[string]any{}
	changesByID := map[string]map[string]any{}
	opsByID := map[string]map[string]any{}
	appendEvent := func(event map[string]any, kind, schema string, refs any) error {
		id := str(event["event_id"])
		if id == "" || eventIDs[id] || event["synthetic"] != synthetic {
			return errors.New("invalid replay event identity/category")
		}
		if e := replaySchema(schema, event); e != nil {
			return e
		}
		eventIDs[id] = true
		events = append(events, event)
		nodes = append(nodes, map[string]any{"id": id, "event_id": id, "kind": kind, "evidence_refs": refs})
		return nil
	}
	for _, v := range network {
		row, ok := obj(v)
		if !ok {
			return nil, nil, errors.New("invalid replay network row")
		}
		event, _ := obj(row["event"])
		obs, _ := obj(row["observation"])
		refs, ok := arr(obs["source_refs"])
		if !ok || len(refs) == 0 || !sameJSON(event["source_ref"], refs[0]) {
			return nil, nil, errors.New("replay network reference projection mismatch")
		}
		if e := appendEvent(event, "network", "ReplayNetworkEvent", refs); e != nil {
			return nil, nil, e
		}
	}
	for _, v := range process {
		row, _ := obj(v)
		event, _ := obj(row["event"])
		if e := appendEvent(event, "process", "ReplayProcessObservation", []any{event["source_ref"]}); e != nil {
			return nil, nil, e
		}
		processByID[str(event["event_id"])] = event
	}
	for _, v := range changes {
		event, _ := obj(v)
		if e := appendEvent(event, "derived_event", "ReplayDerivedEvent", event["evidence_refs"]); e != nil {
			return nil, nil, e
		}
		identity, _ := obj(normalizedJSON(event))
		identity["event_id"] = ""
		hash, e := digestValue(identity)
		if e != nil || event["event_id"] != "change-"+hash {
			return nil, nil, errors.New("replay derived event identity mismatch")
		}
		result, _ := obj(event["result"])
		before, bok := processByID[str(result["before_event_id"])]
		after, aok := processByID[str(result["after_event_id"])]
		refs, _ := arr(event["evidence_refs"])
		if !bok || !aok || len(refs) != 2 || !sameJSON(refs[0], before["source_ref"]) || !sameJSON(refs[1], after["source_ref"]) || !sameJSON(result["before"], before["value"]) || !sameJSON(result["after"], after["value"]) || result["asset_id"] != before["asset_id"] || result["asset_id"] != after["asset_id"] || result["tag"] != before["tag"] || result["tag"] != after["tag"] {
			return nil, nil, errors.New("replay transition original observation mismatch")
		}
		changesByID[str(event["event_id"])] = event
	}
	findings, _ := arr(analysis["rule_findings"])
	for _, v := range findings {
		f, _ := obj(v)
		interval, _ := arr(f["interval"])
		var low, high any
		if len(interval) == 2 {
			var e error
			low, e = pythonUTC(interval[0])
			if e != nil {
				return nil, nil, e
			}
			high, e = pythonUTC(interval[1])
			if e != nil {
				return nil, nil, e
			}
		}
		event := map[string]any{"schema_version": "1.0.0", "synthetic": synthetic, "event_id": f["finding_id"], "event_type": "finite_rule_finding", "rule_version": f["rule_version"], "parameters": f["parameters"], "evidence_refs": f["evidence_refs"], "time_range": map[string]any{"start": low, "end": high}, "result": f}
		event, _ = obj(normalizedJSON(event))
		if e := appendEvent(event, "derived_event", "ReplayDerivedEvent", event["evidence_refs"]); e != nil {
			return nil, nil, e
		}
	}
	for _, v := range operations {
		op, ok := obj(v)
		id := str(op["operation_id"])
		if !ok || id == "" || opsByID[id] != nil {
			return nil, nil, errors.New("invalid replay operation identity")
		}
		opsByID[id] = op
	}
	identityProfile := replaySemanticProfile(profile)
	seen := map[string]bool{}
	for _, v := range candidates {
		c, ok := obj(v)
		if !ok {
			return nil, nil, errors.New("invalid replay candidate")
		}
		id := str(c["candidate_id"])
		op := opsByID[str(c["operation_id"])]
		change := changesByID[str(c["change_id"])]
		hash, e := digestValue([]any{c["operation_id"], c["change_id"], identityProfile})
		if e != nil || id != "candidate-"+hash || seen[id] || op == nil || change == nil {
			return nil, nil, errors.New("replay candidate identity/link mismatch")
		}
		seen[id] = true
		claim, ok := obj(c["claim"])
		if !ok || claim["claim_id"] != id || claim["status"] != "hypothetical" || claim["relation_type"] != "candidate_network_process_association" || claim["synthetic"] != synthetic || claim["rule_id"] != c["rule_id"] || c["config_version"] != profile["config_version"] || c["rule_version"] != profile["rule_version"] {
			return nil, nil, errors.New("replay claim identity mismatch")
		}
		response, _ := obj(op["response"])
		wantRefs, e := replayRefs([]any{op["request_evidence"], response["evidence_refs"], change["evidence_refs"]})
		if e != nil || !sameJSON(claim["evidence_refs"], wantRefs) {
			return nil, nil, errors.New("replay claim original evidence mismatch")
		}
		counter, e := replayRefs(c["counterevidence"])
		if e != nil || !sameJSON(claim["counterevidence"], counter) {
			return nil, nil, errors.New("replay claim counterevidence mismatch")
		}
		if e = replaySchema("ReplayClaim", claim); e != nil {
			return nil, nil, e
		}
		if !sameJSON(c["window"], op["window"]) {
			return nil, nil, errors.New("replay candidate operation window mismatch")
		}
		switch str(c["state"]) {
		case "unknown", "ambiguous", "counterevidence_present", "supported_candidate":
		default:
			return nil, nil, errors.New("unsupported replay candidate state")
		}
		edges = append(edges, map[string]any{"id": id, "source": c["operation_id"], "target": c["change_id"], "claim_id": id, "rule_id": c["rule_id"], "rule_version": c["rule_version"], "config_version": c["config_version"], "config_fingerprint": analysis["config_fingerprint"], "candidate_state": c["state"]})
		claims = append(claims, claim)
	}
	for id, op := range opsByID {
		expected := []any{}
		for _, v := range candidates {
			c, _ := obj(v)
			if c["operation_id"] == id {
				expected = append(expected, c["candidate_id"])
			}
		}
		if !sameJSON(op["candidates"], expected) {
			return nil, nil, errors.New("replay operation candidate index mismatch")
		}
	}
	graph := map[string]any{"schema_version": "1.0.0", "synthetic": synthetic, "nodes": nodes, "edges": edges, "claims": claims, "input_fingerprint": analysis["input_fingerprint"], "core_version": coreVersion, "statistics": map[string]any{"nodes": len(nodes), "edges": len(edges)}, "truncation": map[string]any{"truncated": false, "reason": nil}}
	graph, _ = obj(normalizedJSON(graph))
	hash, e := digestValue(graph)
	if e != nil {
		return nil, nil, e
	}
	graph["graph_id"] = "dual-graph-" + hash
	if e = replaySchema("ReplayGraphArtifact", graph); e != nil {
		return nil, nil, fmt.Errorf("replay graph schema: %w", e)
	}
	return events, graph, nil
}
