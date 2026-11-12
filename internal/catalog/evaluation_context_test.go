package catalog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvaluationReviewContextPreservesFrozenDefinitionsWithoutGoldEvents(t *testing.T) {
	raw := json.RawMessage(`{"split.json":{"blocks":[{"partition":"holdout","normal":true}],"isolation_seconds":60},"registration.json":{"tolerance_seconds":2,"thresholds":{"x":3}},"freeze.json":{"observed_frozen_at":"2026-01-01T00:00:00Z"},"annotations.json":{"origin":"independent","source_ref":"manual","review_ref":"review","annotation_version":"v3","disputed_intervals":[{"batch":"b"}],"events":[{"id":"private-gold"}]},"reference_inventory.json":{"files":["raw-reference"]}}`)
	context := evaluationReviewContext(raw)
	if len(context) != 4 || !strings.Contains(string(context["split"]), `"isolation_seconds":60`) || !strings.Contains(string(context["registration"]), `"thresholds":{"x":3}`) {
		t.Fatalf("frozen definitions lost: %s", context)
	}
	var summary map[string]any
	if json.Unmarshal(context["annotations"], &summary) != nil || summary["annotation_version"] != "v3" || summary["disputed_intervals"] == nil {
		t.Fatalf("annotation provenance lost: %s", context["annotations"])
	}
	if _, ok := summary["events"]; ok {
		t.Fatal("review context leaked gold events")
	}
	encoded, _ := json.Marshal(context)
	if strings.Contains(string(encoded), "private-gold") || strings.Contains(string(encoded), "raw-reference") {
		t.Fatal("context copied unrelated sensitive inventory")
	}
}
