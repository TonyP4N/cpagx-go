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
