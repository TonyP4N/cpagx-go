package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Run only in the disposable /probe mount created by round21_storage_faults.py.
// The 16 MiB write ceiling cannot exhaust an unbounded host filesystem.
func TestR21ActualReadOnlyAndSmallFilesystem(t *testing.T) {
	kind := os.Getenv("CPAG_R21_MOUNT_PROBE")
	if kind == "" {
		t.Skip("dedicated actual mount probe required")
	}
	if kind != "readonly" && kind != "small-full" {
		t.Fatal("unknown actual mount probe")
	}
	before := checkStorage("disposable_probe", "/probe")
	result := map[string]any{"probe": kind, "before": before}
	if kind == "readonly" {
		if before.Accessible || before.Reason == "" {
			t.Fatalf("read-only mount declared usable: %+v", before)
		}
		_, err := os.Create(filepath.Join("/probe", "must-not-write"))
		if !errors.Is(err, syscall.EROFS) {
			t.Fatalf("expected actual EROFS, got %v", err)
		}
		result["actual_write_errno"] = "EROFS"
	} else {
		if !before.Accessible || before.Reason != "storage_space_low" || before.FreeBytes >= minimumReadyFreeBytes {
			t.Fatalf("small filesystem not detected: %+v", before)
		}
		file, err := os.Create(filepath.Join("/probe", "bounded-full"))
		if err != nil {
			t.Fatal(err)
		}
		var written int64
		block := make([]byte, 1<<20)
		var writeErr error
		for i := 0; i < 16; i++ {
			n, e := file.Write(block)
			written += int64(n)
			if e != nil {
				writeErr = e
				break
			}
		}
		file.Close()
		defer os.Remove(file.Name())
		if !errors.Is(writeErr, syscall.ENOSPC) {
			t.Fatalf("bounded filesystem did not return ENOSPC: bytes=%d error=%v", written, writeErr)
		}
		after := checkStorage("disposable_probe", "/probe")
		if after.Reason != "storage_space_low" {
			t.Fatalf("full filesystem readiness: %+v", after)
		}
		result["actual_write_errno"] = "ENOSPC"
		result["written_bytes"] = written
		result["after"] = after
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("R21_STORAGE_PROBE %s\n", raw)
}
