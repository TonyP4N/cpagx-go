// Package contracts validates M1 JSON artifacts against the shared schema subset.
package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

// Validate rejects missing/unknown fields, invalid types, and unsupported versions.
// schemaDir must be the deployment-controlled checked-in schemas directory.
func Validate(schemaDir, name string, data []byte) error {
	if filepath.Base(name) != name {
		return fmt.Errorf("invalid schema name")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("multiple JSON values")
	}
	return validateFile(schemaDir, name+".schema.json", value, name)
}
func validateFile(dir, name string, value any, path string) error {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	var schema map[string]any
	if err = json.Unmarshal(raw, &schema); err != nil {
		return err
	}
	return check(dir, schema, value, path)
}
func check(dir string, s map[string]any, v any, path string) error {
	fail := func(message string) error { return fmt.Errorf("%s: %s", path, message) }
	if ref, ok := s["$ref"].(string); ok {
		return validateFile(dir, ref, v, path)
	}
	if constant, ok := s["const"]; ok && !sameSchemaValue(v, constant) {
		return fail("invalid constant/schema version")
	}
	if options, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range options {
			if sameSchemaValue(v, x) {
				found = true
			}
		}
		if !found {
			return fail("invalid enum")
		}
	}
	if constraint, ok := s["type"]; ok {
		types := []any{constraint}
		if array, ok := constraint.([]any); ok {
			types = array
		}
		match := false
		for _, t := range types {
			switch t {
			case "null":
				match = match || v == nil
			case "object":
				_, ok := v.(map[string]any)
				match = match || ok
			case "array":
				_, ok := v.([]any)
				match = match || ok
			case "string":
				_, ok := v.(string)
				match = match || ok
			case "boolean":
				_, ok := v.(bool)
				match = match || ok
			case "number":
				_, ok := v.(json.Number)
				match = match || ok
			case "integer":
				if n, ok := v.(json.Number); ok {
					_, err := n.Int64()
					match = match || err == nil
				}
			}
		}
		if !match {
			return fail("invalid type")
		}
	}
	switch value := v.(type) {
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		required, _ := s["required"].([]any)
		for _, key := range required {
			if _, ok := value[key.(string)]; !ok {
				return fail("missing " + key.(string))
			}
		}
		for key, item := range value {
			if sub, ok := props[key].(map[string]any); ok {
				if err := check(dir, sub, item, path+"."+key); err != nil {
					return err
				}
			} else if s["additionalProperties"] == false {
				return fail("unknown field " + key)
			} else if sub, ok := s["additionalProperties"].(map[string]any); ok {
				if err := check(dir, sub, item, path+"."+key); err != nil {
					return err
				}
			}
		}
	case []any:
		if minimum, ok := s["minItems"].(float64); ok && float64(len(value)) < minimum {
			return fail("below minimum array length")
		}
		if maximum, ok := s["maxItems"].(float64); ok && float64(len(value)) > maximum {
			return fail("above maximum array length")
		}
		if unique, _ := s["uniqueItems"].(bool); unique {
			seen := map[string]bool{}
			for _, item := range value {
				encoded, err := json.Marshal(item)
				if err != nil {
					return err
				}
				if seen[string(encoded)] {
					return fail("duplicate array item")
				}
				seen[string(encoded)] = true
			}
		}
		sub, _ := s["items"].(map[string]any)
		for i, item := range value {
			if err := check(dir, sub, item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case string:
		if maximum, ok := s["maxLength"].(float64); ok && float64(utf8.RuneCountInString(value)) > maximum {
			return fail("above maximum string length")
		}
		if s["format"] == "date-time" {
			if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
				return fail("invalid date-time")
			}
		}
		if pattern, ok := s["pattern"].(string); ok {
			matched, err := regexp.MatchString(pattern, value)
			if err != nil {
				return err
			}
			if !matched {
				return fail("invalid pattern")
			}
		}
	case json.Number:
		if minimum, ok := s["minimum"].(float64); ok {
			number, _ := value.Float64()
			if number < minimum {
				return fail("below minimum")
			}
		}
		if maximum, ok := s["maximum"].(float64); ok {
			number, _ := value.Float64()
			if number > maximum {
				return fail("above maximum")
			}
		}
	}
	return nil
}

// JSON Schema numeric enum/const values compare numerically. Schema JSON uses
// float64 while artifact parsing deliberately retains json.Number.
func sameSchemaValue(a, b any) bool {
	n, ok := a.(json.Number)
	if ok {
		if f, yes := b.(float64); yes {
			x, valid := new(big.Rat).SetString(string(n))
			y, validY := new(big.Rat).SetString(strconv.FormatFloat(f, 'g', -1, 64))
			return valid && validY && x.Cmp(y) == 0
		}
	}
	return reflect.DeepEqual(a, b)
}
