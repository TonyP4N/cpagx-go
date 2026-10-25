package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSharedSchemas(t *testing.T) {
	dir := "../../schemas"
	entries, err := filepath.Glob(filepath.Join(dir, "*.schema.json"))
	if err != nil || len(entries) != 10 {
		t.Fatalf("ten schemas required: %v", err)
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
	if len(examples) != 10 {
		t.Fatal("ten contract examples required")
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

func TestSharedPacketNegativeMutations(t *testing.T) {
	raw, err := os.ReadFile("../../tests/contracts/examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var examples map[string]json.RawMessage
	if err = json.Unmarshal(raw, &examples); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile("../../tests/contracts/packet-negative-mutations.json")
	if err != nil {
		t.Fatal(err)
	}
	var mutations []struct {
		Label     string `json:"label"`
		Schema    string `json:"schema"`
		Path      string `json:"path"`
		Operation string `json:"operation"`
		Value     any    `json:"value"`
	}
	if err = json.Unmarshal(raw, &mutations); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range mutations {
		t.Run(mutation.Label, func(t *testing.T) {
			var value any
			if e := json.Unmarshal(examples[mutation.Schema], &value); e != nil {
				t.Fatal(e)
			}
			parts := strings.Split(strings.TrimPrefix(mutation.Path, "/"), "/")
			parent := value
			for _, part := range parts[:len(parts)-1] {
				switch item := parent.(type) {
				case map[string]any:
					parent = item[part]
				case []any:
					n, e := strconv.Atoi(part)
					if e != nil {
						t.Fatal(e)
					}
					parent = item[n]
				default:
					t.Fatal("invalid shared mutation path")
				}
			}
			object, ok := parent.(map[string]any)
			if !ok {
				t.Fatal("mutation parent must be object")
			}
			key := parts[len(parts)-1]
			if mutation.Operation == "delete" {
				delete(object, key)
			} else {
				object[key] = mutation.Value
			}
			encoded, e := json.Marshal(value)
			if e != nil {
				t.Fatal(e)
			}
			if Validate("../../schemas", mutation.Schema, encoded) == nil {
				t.Fatal("shared invalid packet mutation accepted")
			}
		})
	}
}
