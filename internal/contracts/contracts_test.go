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
	expected := map[string]bool{}
	for _, name := range []string{"Asset", "Claim", "DatasetManifest", "DerivedEvent", "DualSourceProfile", "EvaluationAnnotations", "EvaluationPredictions", "EvaluationRecord", "EvaluationRegistration", "EvaluationSplit", "GraphArtifact", "NetworkEvent", "PacketObservationArtifact", "ProcessObservation", "RunManifest", "ReplaySourceRef", "ReplayClaim", "ReplayProcessObservation", "ReplayGraphArtifact", "ReplayProfile", "ReplayDerivedEvent", "ReplayNetworkEvent", "ReplayRevision", "ReplayRunManifest", "SingleSourceRunManifest", "DualSpoolProfile", "ReplaySpoolProfile", "ReplaySpoolRunManifest", "DualSharedProfile", "ReplaySharedProfile", "ReplayHistorySpoolManifest", "EvaluationCSVRecordLocator", "EvaluationLocatedReference", "SharedStoreRunManifest", "DualCompactProfile", "ReplayCompactProfile", "CompactStoreRunManifest"} {
		expected[name+".schema.json"] = true
	}
	if err != nil || len(entries) != len(expected) {
		t.Fatalf("explicit baseline and replay schema set required: %v; got %d want %d", err, len(entries), len(expected))
	}
	for _, path := range entries {
		name := filepath.Base(path)
		if !expected[name] {
			t.Fatalf("unregistered schema %s", name)
		}
		delete(expected, name)
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

// Standalone evaluation contracts do not add API endpoints.
func TestEvaluationPreparationContracts(t *testing.T) {
	for filename, name := range map[string]string{"predictions": "EvaluationPredictions", "annotations": "EvaluationAnnotations", "split": "EvaluationSplit", "registration": "EvaluationRegistration"} {
		raw, err := os.ReadFile("../../fixtures/evaluation/" + filename + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate("../../schemas", name, raw); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		value["unexpected"] = true
		bad, _ := json.Marshal(value)
		if Validate("../../schemas", name, bad) == nil {
			t.Fatalf("%s accepted unknown field", name)
		}
	}
}

func TestDualSourceProfile(t *testing.T) {
	raw, err := os.ReadFile("../../profiles/dual-source-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = Validate("../../schemas", "DualSourceProfile", raw); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err = json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["attack_labels"] = []any{}
	bad, _ := json.Marshal(object)
	if Validate("../../schemas", "DualSourceProfile", bad) == nil {
		t.Fatal("labels accepted")
	}
}

func TestDualSourceServiceBounds(t *testing.T) {
	raw, _ := os.ReadFile("../../profiles/dual-source-synthetic.json")
	for _, service := range []any{15, 17, 16.5, "16"} {
		var object map[string]any
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		object["mappings"].([]any)[0].(map[string]any)["service"] = service
		bad, _ := json.Marshal(object)
		if Validate("../../schemas", "DualSourceProfile", bad) == nil {
			t.Fatalf("invalid service accepted: %v", service)
		}
	}
}

func TestNumericEnumsPreserveJSONNumberSemantics(t *testing.T) {
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "Numeric.schema.json"), []byte(`{"type":"object","properties":{"speed":{"type":"number","enum":[1,10]}},"required":["speed"],"additionalProperties":false}`), 0600); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{`{"speed":1}`, `{"speed":1.0}`, `{"speed":10}`, `{"speed":1e1}`} {
		if e := Validate(dir, "Numeric", []byte(raw)); e != nil {
			t.Fatal(raw, e)
		}
	}
	for _, raw := range []string{`{"speed":0}`, `{"speed":1.1}`, `{"speed":"1"}`} {
		if e := Validate(dir, "Numeric", []byte(raw)); e == nil {
			t.Fatal("invalid speed accepted", raw)
		}
	}
}

func TestSingleSourceManifestContract(t *testing.T) {
	raw, err := os.ReadFile("../../tests/contracts/single-source-example.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = Validate("../../schemas", "SingleSourceRunManifest", raw); err != nil {
		t.Fatal(err)
	}
	var original map[string]any
	if err = json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"unknown": true, "single_source_version": "invented", "source_mode": "dual", "attempt_id": 0, "source_presence": map[string]any{"network": "true", "process": false}} {
		var changed map[string]any
		json.Unmarshal(raw, &changed)
		changed[name] = value
		bad, _ := json.Marshal(changed)
		if Validate("../../schemas", "SingleSourceRunManifest", bad) == nil {
			t.Fatalf("invalid %s accepted", name)
		}
	}
}

func TestEvaluationCSVLogicalLocatorContract(t *testing.T) {
	valid := `{"source_ref":"independent-table","sha256":"` + strings.Repeat("a", 64) + `","locator":{"version":"csv-logical-record-1","file_sha256":"` + strings.Repeat("a", 64) + `","record_number":1,"columns":["event_id","time"]}}`
	if err := Validate("../../schemas", "EvaluationLocatedReference", []byte(valid)); err != nil {
		t.Fatal(err)
	}
	mutations := []string{
		strings.Replace(valid, `"record_number":1`, `"record_number":0`, 1),
		strings.Replace(valid, `"record_number":1`, `"record_number":1.5`, 1),
		strings.Replace(valid, `"record_number":1`, `"record_number":true`, 1),
		strings.Replace(valid, `"record_number":1`, `"record_number":1000001`, 1),
		strings.Replace(valid, `["event_id","time"]`, `[]`, 1),
		strings.Replace(valid, `["event_id","time"]`, `["event_id","event_id"]`, 1),
		strings.Replace(valid, `csv-logical-record-1`, `unknown`, 1),
		strings.Replace(valid, `"locator":{`, `"locator":{"unregistered":true,`, 1),
		strings.Replace(valid, `"source_ref":"independent-table"`, `"record":"row:1","source_ref":"independent-table"`, 1),
		strings.Replace(valid, `["event_id","time"]`, `["`+strings.Repeat("x", 4097)+`"]`, 1),
	}
	for i, raw := range mutations {
		if Validate("../../schemas", "EvaluationLocatedReference", []byte(raw)) == nil {
			t.Fatalf("invalid locator %d accepted", i)
		}
	}
}
