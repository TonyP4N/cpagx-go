package catalog

import (
	"strings"
	"testing"
)

func TestDispatchCanaryIsExplicitAndDefaultPoll(t *testing.T) {
	c := Config{WorkerToken: strings.Repeat("w", 32), CoordinatorToken: strings.Repeat("c", 32)}
	if e := validateDispatchConfig(c); e != nil {
		t.Fatal(e)
	}
	s := Server{cfg: c}
	if s.dispatchPartition("canary") != "poll" {
		t.Fatal("default changed")
	}
	c.DispatchMode = "rabbit-canary"
	if validateDispatchConfig(c) == nil {
		t.Fatal("implicit canary accepted")
	}
	c.DispatcherToken = strings.Repeat("d", 32)
	c.RabbitCanaryDatasetIDs = []string{"canary"}
	if e := validateDispatchConfig(c); e != nil {
		t.Fatal(e)
	}
	s.cfg = c
	if s.dispatchPartition("canary") != "rabbit-v3" || s.dispatchPartition("ordinary") != "poll" {
		t.Fatal("allowlist boundary")
	}
	c.DispatcherToken = c.CoordinatorToken
	if validateDispatchConfig(c) == nil {
		t.Fatal("shared authority accepted")
	}
}
