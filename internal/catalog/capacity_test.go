package catalog

import (
	"encoding/json"
	"github.com/TonyP4N/cpagx-go/internal/capacity"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigVersionedCapacityPoliciesAreExplicitAndClosed(t *testing.T) {
	base := Config{DatabaseURL: "postgres://test", SharedRoot: "/tmp/shared", ControlRoot: "/tmp/control", PublicAddr: "127.0.0.1:8095", InternalAddr: "127.0.0.1:8094", WorkerToken: "worker-token-with-sufficient-length", CoordinatorToken: "coordinator-token-with-sufficient-length", BootstrapAdminUsername: "admin", BootstrapAdminPassword: "initial-long-secret"}
	path := filepath.Join(t.TempDir(), "config.json")
	load := func(c Config) (Config, error) {
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(path)
	}
	loaded, err := load(base)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CapacityPolicy != "" || loaded.ResourceProfile != "" {
		t.Fatal("new operator budget enabled by default")
	}
	for _, resource := range []string{capacity.DevelopmentS100, capacity.Engineering} {
		c := base
		c.ResourceProfile = resource
		c.CapacityPolicy = capacity.Engineering
		if _, err = load(c); err != nil {
			t.Fatalf("supported explicit settings rejected: %v", err)
		}
	}
	c := base
	c.ResourceProfile = capacity.EngineeringShared
	c.CapacityPolicy = capacity.EngineeringShared
	if _, err = load(c); err != nil {
		t.Fatal(err)
	}
	c.CapacityPolicy = capacity.Engineering
	if _, err = load(c); err == nil {
		t.Fatal("shared operator policy/resource mismatch accepted")
	}
	for _, change := range []func(*Config){func(c *Config) { c.ResourceProfile = "unknown" }, func(c *Config) { c.CapacityPolicy = "unknown" }} {
		c := base
		change(&c)
		if _, err = load(c); err == nil {
			t.Fatal("unknown operator budget accepted")
		}
	}
}
