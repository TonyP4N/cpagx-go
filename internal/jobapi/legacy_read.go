package jobapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/TonyP4N/cpagx-go/internal/jobs"
)

// Old M4 jobs predate dataset ACLs. The public caller must require an administrator.
// Read only a previously published, anchored success; never complete a historical job.
func (s *Server) LegacyPublished(r *http.Request, id string) ([]VerifiedArtifact, string, error) {
	st, err := s.Repo.Status(r.Context(), id)
	if err != nil {
		return nil, "", err
	}
	if st.State != "succeeded" || st.ArtifactPath == nil || st.ArtifactSHA256 == nil {
		return nil, "", errors.New("no historical publication")
	}
	var p Payload
	if err = json.Unmarshal(st.Payload, &p); err != nil {
		return nil, "", err
	}
	if p.Kind != "" && p.Kind != "packet" {
		return nil, "", errors.New("use the run's original reader")
	}
	if err = s.validHistoricalPayload(p); err != nil {
		return nil, "", err
	}
	base := replayBase(id, st.Attempt)
	anchor, err := jobs.ArtifactKey(jobs.Claim{ID: id, Attempt: st.Attempt}, *st.ArtifactSHA256)
	if err != nil || *st.ArtifactPath != anchor {
		return nil, "", errors.New("wrong historical run or attempt")
	}
	if _, err = s.check(Ref{anchor, *st.ArtifactSHA256}); err != nil {
		return nil, "", err
	}
	path, err := s.file(base + "manifest.json")
	if err != nil {
		return nil, "", err
	}
	raw, err := readFileBounded(path, 65536)
	if err != nil || bytesSHA(raw) != *st.ArtifactSHA256 {
		return nil, "", errors.New("historical publication changed")
	}
	var m Manifest
	if json.Unmarshal(raw, &m) != nil || m.Fingerprint != p.Fingerprint || !publicationInputsMatch(p, m.Inputs, m.Networks) {
		return nil, "", errors.New("historical input mismatch")
	}
	expected := map[string]bool{"dataset.json": true, "events.json": true, "graph.json": true, "quality.json": true, "run_manifest.json": true}
	if p.Kind == "packet" {
		expected["packet_observations.json"] = true
	}
	var items []VerifiedArtifact
	for _, a := range m.Artifacts {
		if !expected[a.Path] {
			return nil, "", errors.New("unsupported historical inventory")
		}
		delete(expected, a.Path)
		n, err := s.checkArtifact(p, Ref{base + a.Path, a.SHA})
		if err != nil || n != a.Size {
			return nil, "", errors.New("historical artifact changed")
		}
		if a.Path == "run_manifest.json" {
			path, err := s.file(base + a.Path)
			if err != nil {
				return nil, "", err
			}
			core, err := readFileBounded(path, 65536)
			var version struct {
				Schema    string `json:"schema_version"`
				Synthetic bool   `json:"synthetic"`
			}
			if err != nil || bytesSHA(core) != a.SHA || json.Unmarshal(core, &version) != nil || version.Schema != "1.0.0" || !version.Synthetic {
				return nil, "", errors.New("unsupported historical contract")
			}
		}
		items = append(items, VerifiedArtifact{a.Path, a.SHA, a.Size})
	}
	if len(expected) != 0 {
		return nil, "", errors.New("incomplete historical inventory")
	}
	return items, base, nil
}

func (s *Server) OpenLegacyArtifact(r *http.Request, base string, item VerifiedArtifact) (*os.File, error) {
	limit, err := s.artifactLimit(Payload{})
	if err != nil {
		return nil, err
	}
	return s.openArtifactSnapshot(r, base+item.Path, item.Size, item.SHA, limit)
}
