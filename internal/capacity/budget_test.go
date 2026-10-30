package capacity

import "testing"

func TestVersionedBudgetsAreFiniteAndOldDefaultUnchanged(t *testing.T) {
	old, err := Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if old.NetworkFileBytes != 16<<20 || old.NetworkTotalBytes != 16<<20 || old.ProcessBytes != 2<<20 || old.ProcessRecords != 1000 || old.ProfileBytes != 65536 || old.Operations != 100 {
		t.Fatalf("old bounds changed: %+v", old)
	}
	current, err := Resolve(Engineering)
	if err != nil {
		t.Fatal(err)
	}
	if current.NetworkFiles != 4 || current.NetworkFileBytes != 64<<20 || current.NetworkTotalBytes != 128<<20 || current.ProcessBytes != 8<<20 || current.ProcessRecords != 10000 || current.ProcessColumns != 16 || current.Frames != 100000 || current.OutputBytes != 1<<30 {
		t.Fatalf("target changed: %+v", current)
	}
	for _, value := range []any{"", nil, 42, "future-capacity"} {
		if _, err := FromDocument(map[string]any{"capacity_profile": value, "analysis_mode": "bounded-real-capable-v1"}); err == nil {
			t.Fatalf("accepted unsupported binding %v", value)
		}
	}
	if _, err := FromDocument(map[string]any{"capacity_profile": Engineering}); err == nil {
		t.Fatal("implicit analysis mode accepted")
	}
	for version, expected := range map[string]int64{"": 64 << 20, DevelopmentS100: 512 << 20, Engineering: 1 << 30} {
		actual, err := ArtifactBytes(version)
		if err != nil || actual != expected {
			t.Fatalf("resource %q: %d %v", version, actual, err)
		}
	}
	if _, err := ArtifactBytes("unbounded"); err == nil {
		t.Fatal("unknown resource policy accepted")
	}
}

func TestTargetInputBoundaryAndPlusOne(t *testing.T) {
	b, _ := Resolve(Engineering)
	for _, sizes := range [][]int64{{64 << 20}, {64 << 20, 64 << 20}, {32 << 20, 32 << 20, 32 << 20, 32 << 20}} {
		if err := b.CheckInputSizes(sizes, 8<<20, 8<<20); err != nil {
			t.Fatal(err)
		}
	}
	for _, sizes := range [][]int64{{(64 << 20) + 1}, {64 << 20, 64 << 20, 1}, {1, 1, 1, 1, 1}, {-1}} {
		if err := b.CheckInputSizes(sizes, 8<<20, 8<<20); err == nil {
			t.Fatalf("accepted +1/invalid boundary: %v", sizes)
		}
	}
	if err := b.CheckInputSizes([]int64{1}, (8<<20)+1, 1); err == nil {
		t.Fatal("CSV +1 byte accepted")
	}
	if err := b.CheckInputSizes([]int64{1}, 1, (8<<20)+1); err == nil {
		t.Fatal("configuration +1 byte accepted")
	}
	old, _ := Resolve("")
	if err := old.CheckInputSizes([]int64{(16 << 20) + 1}, 1, 1); err == nil {
		t.Fatal("old byte guard expanded")
	}
}

func TestSharedBudgetsRequireAllExplicitVersionBindings(t *testing.T) {
	doc := map[string]any{"capacity_profile": EngineeringShared, "storage_format": SharedFormat, "analysis_mode": "bounded-real-capable-v1"}
	b, err := FromDocument(doc)
	if err != nil || b.Candidates != 500000 || b.Snapshots != 65000 || b.Revisions != 90000 {
		t.Fatalf("shared bounds: %+v %v", b, err)
	}
	old, _ := Resolve(Engineering)
	if old.Candidates != 100000 || old.Snapshots != 45000 {
		t.Fatal("capacity1 was reinterpreted")
	}
	for _, bad := range []map[string]any{
		{"storage_format": SharedFormat},
		{"capacity_profile": Engineering, "storage_format": SharedFormat, "analysis_mode": "bounded-real-capable-v1"},
		{"capacity_profile": EngineeringShared, "analysis_mode": "bounded-real-capable-v1"},
		{"capacity_profile": EngineeringShared, "storage_format": SharedFormat, "analysis_mode": "bounded-real-capable-v1", "replay": map[string]any{"history_format": SharedFormat}},
	} {
		if _, err := FromDocument(bad); err == nil {
			t.Fatalf("incomplete shared binding accepted: %v", bad)
		}
	}
	doc["replay"] = map[string]any{"history_format": SharedFormat, "identity_strategy": "merkle-json-dag-1", "prefix_digest_strategy": "incremental-prefix-digest-2"}
	if _, err := FromDocument(doc); err != nil {
		t.Fatal(err)
	}
	a, _ := ArtifactBytes(Engineering)
	c, _ := ArtifactBytes(EngineeringShared)
	if a != c {
		t.Fatal("shared version expanded physical resource budget")
	}
	first, _ := HTTPTimeouts(Engineering)
	second, _ := HTTPTimeouts(EngineeringShared)
	if first != second {
		t.Fatal("shared version expanded HTTP timeout")
	}
}

func TestCompactBudgetDoesNotRaisePhysicalQuotas(t *testing.T) {
	doc := map[string]any{"capacity_profile": EngineeringCore, "storage_format": CoreSharedFormat, "storage_budget_version": "shared-storage-budget-2", "analysis_mode": "bounded-real-capable-v1"}
	b, err := FromDocument(doc)
	if err != nil || b.OutputBytes != 1<<30 || b.Snapshots != 65000 || b.Candidates != 500000 {
		t.Fatalf("compact bounds: %+v %v", b, err)
	}
	delete(doc, "storage_budget_version")
	if _, err = FromDocument(doc); err == nil {
		t.Fatal("implicit storage budget accepted")
	}
	if actual, err := ArtifactBytes(StorageBudget); err != nil || actual != 1<<30 {
		t.Fatalf("physical budget: %d %v", actual, err)
	}
}
