package catalog

import (
	"reflect"
	"testing"
)

func TestReplayGraphProjectionRetainsVerifiedEnvelopeVersion(t *testing.T) {
	graph := map[string]any{"nodes": []any{}, "edges": []any{}}
	analysis := map[string]any{"synthetic": false}
	version := "dual-source-replay-1"
	for name, response := range map[string]any{
		"final":    map[string]any{"mode": "dual_source_replay", "replay_version": version, "data": map[string]any{"analysis": analysis, "graph": graph}},
		"snapshot": map[string]any{"replay_version": version, "snapshot_number": 3, "revision_number": 2, "analysis": analysis, "graph": graph},
	} {
		t.Run(name, func(t *testing.T) {
			out := replayGraphProjection(response)
			if out["replay_version"] != version || out["synthetic"] != false || !reflect.DeepEqual(out["graph"], graph) {
				t.Fatalf("graph projection lost verified metadata: %#v", out)
			}
		})
	}
	unknown := replayGraphProjection(map[string]any{"data": map[string]any{"analysis": analysis, "graph": graph}})
	if unknown["replay_version"] != nil {
		t.Fatal("missing trusted version was guessed")
	}
}
