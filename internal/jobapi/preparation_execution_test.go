package jobapi

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestPreparationCommandRequiresExplicitBoundedContext(t *testing.T) {
	args := []string{"-m", "cpag_core.evaluation_artifacts", "--projection", "dual"}
	got, files, err := GuardPreparationCommand(context.Background(), args)
	if err != nil || !reflect.DeepEqual(got, args) || files != nil {
		t.Fatal("legacy invocation changed")
	}
	lock, err := os.CreateTemp(t.TempDir(), "lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx := WithPreparationExecution(context.Background(), lock, t.TempDir())
	if _, _, err = GuardPreparationCommand(ctx, args); err == nil {
		t.Fatal("unbounded preparation accepted")
	}
	deadline, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	got, files, err = GuardPreparationCommand(deadline, args)
	if err != nil || len(files) != 1 || files[0] != lock || got[1] != "cpag_core.evaluation_preparation_guard" {
		t.Fatalf("guard missing: %v %v", got, err)
	}
	for _, args := range [][]string{{"-c", "arbitrary"}, {"-m", "unlisted"}, {"-m", "cpag_core.evaluation_bundle"}} {
		if _, _, err = GuardPreparationCommand(deadline, args); err == nil {
			t.Fatal("unlisted module accepted")
		}
	}
}
