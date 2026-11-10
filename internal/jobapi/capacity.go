package jobapi

import (
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/TonyP4N/cpagx-go/internal/capacity"
	"io"
	"os"
)

func (s *Server) payloadBudget(p Payload, config map[string]any) (capacity.Budget, error) {
	b, err := readPayloadBudget(p, config)
	if err != nil {
		return b, err
	}
	if b.Version != "" && s.CapacityPolicy != b.Version {
		return b, errors.New("capacity profile requires explicit operator site policy")
	}
	if dualFamily(p.Kind) && p.ResourceProfile != s.ResourceProfile {
		return b, errors.New("payload/operator resource profile mismatch")
	}
	return b, nil
}

// Historical reads use the immutable payload/profile binding and its supported
// limits. A new operator policy cannot silently enlarge or reinterpret them.
// Submission and unfinished publication must continue using payloadBudget.
func readPayloadBudget(p Payload, config map[string]any) (capacity.Budget, error) {
	if p.HistoryFormat != "" && (p.Kind != "dual-source-replay" || p.HistoryFormat != ReplaySpoolFormat && p.HistoryFormat != capacity.SharedFormat && p.HistoryFormat != capacity.CoreSharedFormat) {
		return capacity.Budget{}, errors.New("history format requires explicit supported replay payload")
	}
	b, err := capacity.FromDocument(config)
	if err != nil {
		return b, err
	}
	if str(config["storage_format"]) != p.StorageFormat {
		return b, errors.New("payload/profile storage format mismatch")
	}
	if b.Version == capacity.EngineeringCore {
		if p.StorageBudgetVersion != SharedStorageBudget || config["storage_budget_version"] != SharedStorageBudget {
			return b, errors.New("compact storage budget binding mismatch")
		}
		if !dualFamily(p.Kind) || p.StorageFormat != capacity.CoreSharedFormat || p.ResourceProfile != capacity.StorageBudget || (p.Kind == "dual-source-replay" && p.HistoryFormat != capacity.CoreSharedFormat) {
			return b, errors.New("compact capacity requires explicit DAG6 and storage budget binding")
		}
	} else if p.StorageBudgetVersion != "" {
		return b, errors.New("storage budget requires compact capacity")
	} else if p.StorageFormat == capacity.CoreSharedFormat || p.ResourceProfile == capacity.StorageBudget || p.HistoryFormat == capacity.CoreSharedFormat {
		return b, errors.New("compact version mismatch")
	} else if b.Version == capacity.EngineeringShared {
		if !dualFamily(p.Kind) || p.StorageFormat != capacity.SharedFormat || p.ResourceProfile != capacity.EngineeringShared || (p.Kind == "dual-source-replay" && p.HistoryFormat != capacity.SharedFormat && p.HistoryFormat != capacity.CoreSharedFormat) {
			return b, errors.New("shared capacity requires bound storage, resource and replay versions")
		}
	} else if p.StorageFormat != "" || p.ResourceProfile == capacity.EngineeringShared || p.HistoryFormat == capacity.SharedFormat {
		return b, errors.New("shared execution cannot reinterpret historical capacity")
	}
	if b.Version != p.CapacityProfile {
		return b, errors.New("payload/profile capacity binding mismatch")
	}
	if b.Version != "" {
		if p.Kind != "dual-source" && !(p.Kind == "dual-source-replay" && (p.HistoryFormat == ReplaySpoolFormat || p.HistoryFormat == capacity.SharedFormat || p.HistoryFormat == capacity.CoreSharedFormat)) {
			return b, errors.New("capacity profile requires versioned replay integration")
		}
	}
	if !dualFamily(p.Kind) && p.ResourceProfile == "" && p.CapacityProfile == "" {
		return b, nil
	}
	if _, err = capacity.ArtifactBytes(p.ResourceProfile); err != nil {
		return b, err
	}
	return b, nil
}

func payloadLimits(p Payload) (capacity.Budget, error) { return capacity.Resolve(p.CapacityProfile) }

func (s *Server) artifactLimit(p Payload) (int64, error) {
	return capacity.ArtifactBytes(p.ResourceProfile)
}

func (s *Server) checkArtifact(p Payload, ref Ref) (int64, error) {
	limit, err := s.artifactLimit(p)
	if err != nil {
		return 0, err
	}
	return s.checkBounded(ref, limit)
}

// Validate CSV logical records before enqueue, without interpreting values or
// accepting malformed data by trimming records. Quoted newlines stay one row.
func (s *Server) validateProcessBudget(p Payload, b capacity.Budget) error {
	path, err := s.file(p.Process.Path)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil || len(header) == 0 || len(header) > b.ProcessColumns {
		return errors.New("process column budget exceeded or invalid header")
	}
	for n := 0; ; n++ {
		row, e := reader.Read()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return fmt.Errorf("invalid process logical record: %w", e)
		}
		if n >= b.ProcessRecords {
			return errors.New("process logical record budget exceeded")
		}
		if len(row) != len(header) {
			return errors.New("process logical record width mismatch")
		}
	}
}
