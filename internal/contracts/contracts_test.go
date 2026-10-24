package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSharedSchemas(t *testing.T) {
	dir := "../../schemas"
	entries, err := filepath.Glob(filepath.Join(dir, "*.schema.json"))
	if err != nil || len(entries) != 9 {
		t.Fatalf("nine schemas required: %v", err)
	}
	for _, path := range entries {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err = json.Unmarshal(raw, &schema); err != nil {
			t.Fatal(err)
		}
		if schema["additionalProperties"] != false {
			t.Fatal(path + " must reject unknown fields")
		}
	}
	valid := []byte(`{"schema_version":"1.0.0","synthetic":true,"asset_id":"test","role":"unknown","aliases":[],"process_stage":null,"valid_time":{"start":null,"end":null},"config_version":"m1"}`)
	if err = Validate(dir, "Asset", valid); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	json.Unmarshal(valid, &object)
	for _, change := range []func(){func() { object["unknown"] = true }, func() { delete(object, "unknown"); object["schema_version"] = "2.0.0" }, func() { object["schema_version"] = "1.0.0"; delete(object, "asset_id") }} {
		change()
		raw, _ := json.Marshal(object)
		if Validate(dir, "Asset", raw) == nil {
			t.Fatal("invalid contract accepted")
		}
	}
}

func TestAllSharedExamples(t *testing.T) {
	raw, err := os.ReadFile("../../tests/contracts/examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var examples map[string]json.RawMessage
	if err = json.Unmarshal(raw, &examples); err != nil {
		t.Fatal(err)
	}
	if len(examples) != 9 {
		t.Fatal("nine contract examples required")
	}
	for name, data := range examples {
		if err = Validate("../../schemas", name, data); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var object map[string]any
		json.Unmarshal(data, &object)
		object["schema_version"] = "unsupported"
		changed, _ := json.Marshal(object)
		if Validate("../../schemas", name, changed) == nil {
			t.Fatalf("%s accepted unknown version", name)
		}
	}
}

func TestTypedConstantsAndTimes(t *testing.T) {
	raw, err := os.ReadFile("../../tests/contracts/examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var examples map[string]map[string]any
	if err = json.Unmarshal(raw, &examples); err != nil {
		t.Fatal(err)
	}
	evaluation := examples["EvaluationRecord"]
	evaluation["independent_labels"] = 1
	changed, _ := json.Marshal(evaluation)
	if Validate("../../schemas", "EvaluationRecord", changed) == nil {
		t.Fatal("numeric true accepted")
	}
	asset := examples["Asset"]
	for _, timestamp := range []string{"2026-01-01T00:00:00", "2026-02-30T00:00:00Z", "arbitrary"} {
		asset["valid_time"].(map[string]any)["start"] = timestamp
		changed, _ = json.Marshal(asset)
		if Validate("../../schemas", "Asset", changed) == nil {
			t.Fatal("invalid timestamp accepted")
		}
	}
}
