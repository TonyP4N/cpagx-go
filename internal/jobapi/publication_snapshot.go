package jobapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
)

const PublicationSnapshotVersion = "verified-publication-snapshot-1"

type VerifiedArtifact struct {
	Path string `json:"path"`
	SHA  string `json:"sha256"`
	Size int64  `json:"size_bytes"`
}

// Created only after the ordinary complete publication verifier succeeds.
// Catalog stores this in its own preparation table; no HTTP body is decoded as
// an approval. RecheckPublicationSnapshot checks actual bytes on every reuse.
type PublicationSnapshot struct {
	Version            string             `json:"version"`
	RunID              string             `json:"run_id"`
	Attempt            int                `json:"attempt_id"`
	PayloadSHA256      string             `json:"payload_sha256"`
	ArtifactPath       string             `json:"artifact_path"`
	PublicationSHA256  string             `json:"publication_sha256"`
	CoreManifestSHA256 string             `json:"core_manifest_sha256"`
	ConfigFingerprint  string             `json:"config_fingerprint"`
	InputFingerprint   string             `json:"input_fingerprint"`
	Mode               string             `json:"mode"`
	Files              []VerifiedArtifact `json:"files"`
}

func (s *Server) CapturePublicationSnapshot(r *http.Request, id string) (PublicationSnapshot, error) {
	items, base, err := s.VerifiedDualArtifacts(r, id)
	if err != nil {
		return PublicationSnapshot{}, err
	}
	st, err := s.Repo.Status(r.Context(), id)
	if err != nil {
		return PublicationSnapshot{}, err
	}
	if st.State != "succeeded" || st.ArtifactPath == nil || st.ArtifactSHA256 == nil || replayBase(id, st.Attempt) != base {
		return PublicationSnapshot{}, errors.New("publication changed during snapshot")
	}
	payloadSHA, err := DualProfileFingerprint(st.Payload)
	if err != nil {
		return PublicationSnapshot{}, err
	}
	result := PublicationSnapshot{Version: PublicationSnapshotVersion, RunID: id, Attempt: st.Attempt, PayloadSHA256: payloadSHA, ArtifactPath: *st.ArtifactPath, PublicationSHA256: *st.ArtifactSHA256}
	for _, item := range items {
		result.Files = append(result.Files, VerifiedArtifact{item.Path, item.SHA, item.Size})
		if item.Path == "run_manifest.json" {
			result.CoreManifestSHA256 = item.SHA
		}
	}
	path, err := s.file(base + "run_manifest.json")
	if err != nil {
		return result, err
	}
	raw, err := readFileBounded(path, 65536)
	if err != nil || bytesSHA(raw) != result.CoreManifestSHA256 {
		return result, errors.New("core manifest changed during preparation snapshot")
	}
	var core struct {
		RunID   string `json:"run_id"`
		Attempt int    `json:"attempt_id"`
		Config  string `json:"config_fingerprint"`
		Input   string `json:"input_fingerprint"`
		Mode    string `json:"mode"`
	}
	if json.Unmarshal(raw, &core) != nil || core.RunID != id || core.Attempt != st.Attempt || !shaPattern.MatchString(core.Input) || !shaPattern.MatchString(core.Config) {
		return result, errors.New("invalid prepared core identity")
	}
	result.ConfigFingerprint = core.Config
	result.InputFingerprint = core.Input
	result.Mode = core.Mode
	if _, _, err = s.RecheckPublicationSnapshot(r, id, result); err != nil {
		return result, err
	}
	return result, nil
}

func snapshotHashFile(ctx context.Context, path, digest string, size, limit int64) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size || size < 0 || size > limit {
		return errors.New("prepared artifact byte budget or size mismatch")
	}
	hash := sha256.New()
	buffer := make([]byte, 1024*1024)
	var total int64
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		n, e := file.Read(buffer)
		if n > 0 {
			total += int64(n)
			hash.Write(buffer[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
	}
	if total != size || fmt.Sprintf("%x", hash.Sum(nil)) != digest {
		return errors.New("prepared artifact bytes changed")
	}
	return nil
}

// Reuse a prior *service-created* semantic approval, while checking current DB
// identity, original inputs, every publication byte, exact inventory and budget.
// This method intentionally does not reconstruct the large semantic DOM.
func (s *Server) RecheckPublicationSnapshot(r *http.Request, id string, expected PublicationSnapshot) ([]VerifiedArtifact, string, error) {
	if expected.Version != PublicationSnapshotVersion || expected.RunID != id || expected.Attempt < 1 || !shaPattern.MatchString(expected.PayloadSHA256) || !shaPattern.MatchString(expected.PublicationSHA256) {
		return nil, "", errors.New("unsupported prepared publication snapshot")
	}
	st, err := s.Repo.Status(r.Context(), id)
	if err != nil {
		return nil, "", err
	}
	payloadSHA, err := DualProfileFingerprint(st.Payload)
	if err != nil {
		return nil, "", err
	}
	if st.State != "succeeded" || st.Attempt != expected.Attempt || st.ArtifactPath == nil || *st.ArtifactPath != expected.ArtifactPath || st.ArtifactSHA256 == nil || *st.ArtifactSHA256 != expected.PublicationSHA256 || payloadSHA != expected.PayloadSHA256 {
		return nil, "", errors.New("prepared publication database identity changed")
	}
	var payload Payload
	if err = json.Unmarshal(st.Payload, &payload); err != nil {
		return nil, "", err
	}
	if !dualFamily(payload.Kind) {
		return nil, "", errors.New("prepared publication kind unsupported")
	}
	if err = s.validHistoricalPayload(payload); err != nil {
		return nil, "", err
	}
	base := replayBase(id, st.Attempt)
	if expected.ArtifactPath != base+expected.PublicationSHA256+".json" {
		return nil, "", errors.New("prepared publication anchor path mismatch")
	}
	path, err := s.file(base + "manifest.json")
	if err != nil {
		return nil, "", err
	}
	raw, err := readFileBounded(path, 65536)
	if err != nil || bytesSHA(raw) != expected.PublicationSHA256 {
		return nil, "", errors.New("prepared publication wrapper changed")
	}
	anchor, err := s.file(expected.ArtifactPath)
	if err != nil {
		return nil, "", err
	}
	anchorRaw, err := readFileBounded(anchor, 65536)
	if err != nil || !bytes.Equal(raw, anchorRaw) {
		return nil, "", errors.New("prepared content-addressed publication changed")
	}
	var wrapper Manifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wrapper) != nil || decoder.Decode(new(any)) != io.EOF || wrapper.Fingerprint != payload.Fingerprint || !publicationInputsMatch(payload, wrapper.Inputs, wrapper.Networks) || wrapper.ReplayVersion != payload.ReplayVersion || wrapper.HistoryFormat != payload.HistoryFormat {
		return nil, "", errors.New("prepared publication binding mismatch")
	}
	actual := []VerifiedArtifact{}
	seen := map[string]bool{}
	var total int64
	limit, err := s.artifactLimit(payload)
	if err != nil {
		return nil, "", err
	}
	for _, item := range wrapper.Artifacts {
		if seen[item.Path] || !validPayloadArtifactPath(payload, item.Path) || !shaPattern.MatchString(item.SHA) {
			return nil, "", errors.New("prepared artifact inventory invalid")
		}
		seen[item.Path] = true
		actual = append(actual, VerifiedArtifact{item.Path, item.SHA, item.Size})
		path, err := s.file(base + item.Path)
		if err != nil {
			return nil, "", err
		}
		bound := limit
		if strings.HasSuffix(item.Path, "manifest.json") {
			bound = 65536
		}
		if err = snapshotHashFile(r.Context(), path, item.SHA, item.Size, bound); err != nil {
			return nil, "", err
		}
		total += item.Size
	}
	if !reflect.DeepEqual(actual, expected.Files) {
		return nil, "", errors.New("prepared approved inventory changed")
	}
	if payload.ResourceProfile != "" && total > limit {
		return nil, "", errors.New("prepared aggregate output budget exceeded")
	}
	if payload.Kind == "dual-source" {
		err = s.dualInventory(base, payload)
	} else if payload.HistoryFormat == ReplaySpoolFormat {
		err = s.spoolInventory(base, payload)
	} else {
		err = s.replayInventory(base, payload)
	}
	if err != nil {
		return nil, "", err
	}
	after, err := s.Repo.Status(r.Context(), id)
	if err != nil {
		return nil, "", err
	}
	afterPayload, err := DualProfileFingerprint(after.Payload)
	if err != nil || after.State != st.State || after.Attempt != st.Attempt || after.ArtifactPath == nil || *after.ArtifactPath != expected.ArtifactPath || after.ArtifactSHA256 == nil || *after.ArtifactSHA256 != expected.PublicationSHA256 || afterPayload != payloadSHA {
		return nil, "", errors.New("publication changed during prepared byte verification")
	}
	return actual, base, nil
}
