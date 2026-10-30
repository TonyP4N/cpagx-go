package catalog

import (
	"encoding/json"
	"errors"
	"github.com/TonyP4N/cpagx-go/internal/capacity"
)

func (s *Server) configBudget(raw []byte) (capacity.Budget, error) {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil || doc == nil {
		return capacity.Budget{}, errors.New("invalid configuration object")
	}
	b, err := capacity.FromDocument(doc)
	if err != nil {
		return b, err
	}
	if b.Version != "" && b.Version != s.cfg.CapacityPolicy {
		return b, errors.New("capacity profile requires explicit site policy")
	}
	if int64(len(raw)) > b.ProfileBytes {
		return b, errors.New("configuration exceeds versioned byte budget")
	}
	return b, nil
}

func (s *Server) configBodyLimit() int64 {
	if capacity.IsEngineering(s.cfg.CapacityPolicy) {
		return (8 << 20) + 65536
	}
	return 65536
}
