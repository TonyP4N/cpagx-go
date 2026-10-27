package catalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const snapshotVersion = "v3-preflight-snapshot-1"

var errNoSourceFiles = errors.New("no source files")

// PreflightSnapshot binds a report to its exact historical catalog selection.
// JSON is stored as text, and SHA256 covers those precise UTF-8 bytes.
type PreflightSnapshot struct {
	SchemaVersion string          `json:"schema_version"`
	Origin        string          `json:"origin"`
	Dataset       SnapshotDataset `json:"dataset"`
	Files         []SnapshotFile  `json:"files"`
	Config        SnapshotConfig  `json:"config"`
	Manifest      json.RawMessage `json:"manifest"`
}
type SnapshotDataset struct {
	ID               string `json:"id"`
	SourceKind       string `json:"source_kind"`
	Source           string `json:"source"`
	Batch            string `json:"batch"`
	AuthorizationRef string `json:"authorization_ref"`
}
type SnapshotFile struct {
	DatasetFileID string `json:"dataset_file_id"`
	SourceFileID  string `json:"source_file_id"`
	Role          string `json:"role"`
	Filename      string `json:"filename"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	SizeBytes     int64  `json:"size_bytes"`
}
type SnapshotConfig struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Version     int             `json:"version"`
	Path        string          `json:"path"`
	SHA256      string          `json:"sha256"`
	Fingerprint string          `json:"fingerprint"`
	Document    json.RawMessage `json:"document"`
}

func snapshotBytes(snap PreflightSnapshot) ([]byte, string, error) {
	raw, e := json.Marshal(snap)
	if e != nil {
		return nil, "", e
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}
func parseSnapshot(raw []byte, sha, status string) (PreflightSnapshot, error) {
	var snap PreflightSnapshot
	if !shaRE.MatchString(sha) {
		return snap, errors.New("invalid snapshot digest")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != sha {
		return snap, errors.New("preflight snapshot changed")
	}
	if e := json.Unmarshal(raw, &snap); e != nil {
		return snap, e
	}
	if snap.SchemaVersion != snapshotVersion || snap.Origin != status || len(snap.Files) == 0 || snap.Config.Kind != "intake" {
		return snap, errors.New("unsupported preflight snapshot")
	}
	return snap, nil
}
func sameSnapshotInputs(a, b PreflightSnapshot) bool {
	var ad, bd, am, bm any
	if json.Unmarshal(a.Config.Document, &ad) != nil || json.Unmarshal(b.Config.Document, &bd) != nil || json.Unmarshal(a.Manifest, &am) != nil || json.Unmarshal(b.Manifest, &bm) != nil {
		return false
	}
	a.Config.Document = nil
	b.Config.Document = nil
	a.Manifest = nil
	b.Manifest = nil
	a.Origin = ""
	b.Origin = ""
	return reflect.DeepEqual(a, b) && reflect.DeepEqual(ad, bd) && reflect.DeepEqual(am, bm)
}

// buildSnapshot resolves the catalog at one selection point. A cutoff is used
// only for explicit legacy reconstruction; it never guesses by current files.
func (s *Server) buildSnapshot(ctx context.Context, dataset, configID, origin string, cutoff *time.Time) (PreflightSnapshot, error) {
	snap := PreflightSnapshot{SchemaVersion: snapshotVersion, Origin: origin, Files: []SnapshotFile{}}
	if e := s.DB.QueryRowContext(ctx, `SELECT id,source_kind,source,batch,authorization_ref FROM v3_datasets WHERE id=$1`, dataset).Scan(&snap.Dataset.ID, &snap.Dataset.SourceKind, &snap.Dataset.Source, &snap.Dataset.Batch, &snap.Dataset.AuthorizationRef); e != nil {
		return snap, e
	}
	var dbDocument []byte
	if e := s.DB.QueryRowContext(ctx, `SELECT id,kind,version,profile_storage_path,profile_sha256,config_fingerprint,profile_json FROM v3_config_versions WHERE dataset_id=$1 AND id=$2`, dataset, configID).Scan(&snap.Config.ID, &snap.Config.Kind, &snap.Config.Version, &snap.Config.Path, &snap.Config.SHA256, &snap.Config.Fingerprint, &dbDocument); e != nil {
		return snap, e
	}
	if snap.Config.Kind != "intake" {
		return snap, errors.New("intake configuration required")
	}
	prefix := filepath.Join("inputs", "catalog", dataset) + string(filepath.Separator)
	if !strings.HasPrefix(snap.Config.Path, prefix) {
		return snap, errors.New("configuration belongs to another dataset")
	}
	profilePath, e := s.verifiedFileHash(snap.Config.Path, snap.Config.SHA256)
	if e != nil {
		return snap, e
	}
	profileRaw, e := os.ReadFile(profilePath)
	if e != nil {
		return snap, e
	}
	if e = validateUniqueJSON(profileRaw); e != nil {
		return snap, fmt.Errorf("ambiguous configuration JSON: %w", e)
	}
	var fileValue, dbValue any
	if json.Unmarshal(profileRaw, &fileValue) != nil || json.Unmarshal(dbDocument, &dbValue) != nil || !reflect.DeepEqual(fileValue, dbValue) {
		return snap, errors.New("configuration document differs from catalog")
	}
	snap.Config.Document = json.RawMessage(profileRaw)
	var selectedBefore any
	if cutoff != nil {
		selectedBefore = *cutoff
	}
	rows, e := s.DB.QueryContext(ctx, `SELECT f.id,f.source_file_id,f.role,f.filename,x.storage_path,x.sha256,x.size_bytes FROM v3_dataset_files f JOIN v3_source_files x ON x.id=f.source_file_id WHERE f.dataset_id=$1 AND ($2::timestamptz IS NULL OR f.created_at<=$2::timestamptz) ORDER BY f.id`, dataset, selectedBefore)
	if e != nil {
		return snap, e
	}
	defer rows.Close()
	for rows.Next() {
		var f SnapshotFile
		if e = rows.Scan(&f.DatasetFileID, &f.SourceFileID, &f.Role, &f.Filename, &f.Path, &f.SHA256, &f.SizeBytes); e != nil {
			return snap, e
		}
		if !strings.HasPrefix(f.Path, prefix) {
			return snap, errors.New("source file belongs to another dataset")
		}
		if _, e = s.verifiedFile(f.Path, f.SHA256, f.SizeBytes); e != nil {
			return snap, fmt.Errorf("source %s integrity: %w", f.DatasetFileID, e)
		}
		snap.Files = append(snap.Files, f)
	}
	if e = rows.Err(); e != nil {
		return snap, e
	}
	if len(snap.Files) == 0 {
		return snap, errNoSourceFiles
	}
	entries := make([]map[string]any, 0, len(snap.Files))
	for _, f := range snap.Files {
		entries = append(entries, map[string]any{"name": f.Path, "sha256": f.SHA256, "size_bytes": f.SizeBytes, "kind": f.Role})
	}
	manifest := map[string]any{"schema_version": "1.0.0", "synthetic": snap.Dataset.SourceKind == "synthetic", "dataset_id": dataset, "source": snap.Dataset.Source, "release": snap.Dataset.Batch, "files": entries, "collection_range": map[string]any{"start": nil, "end": nil}, "timezone_basis": nil, "authorization_ref": snap.Dataset.AuthorizationRef}
	snap.Manifest, e = json.Marshal(manifest)
	if e != nil {
		return snap, e
	}
	return snap, nil
}

// An old report is compared by JSON value, not the formatting PostgreSQL gave
// its jsonb column. Snapshot hashes remain byte-exact.
func sameReport(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}
func configAndManifest(snap PreflightSnapshot) ([]byte, []byte, error) {
	if !json.Valid(snap.Config.Document) || !json.Valid(snap.Manifest) {
		return nil, nil, errors.New("invalid snapshot JSON")
	}
	return bytes.Clone(snap.Config.Document), bytes.Clone(snap.Manifest), nil
}

// The backup parser rejects duplicate keys; accept the same unambiguous JSON
// subset at config creation and legacy reconstruction.
func validateUniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var visit func() error
	visit = func() error {
		tok, e := d.Token()
		if e != nil {
			return e
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					keyToken, e := d.Token()
					if e != nil {
						return e
					}
					key, ok := keyToken.(string)
					if !ok {
						return errors.New("object key required")
					}
					if seen[key] {
						return errors.New("duplicate JSON key")
					}
					seen[key] = true
					if e = visit(); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			case '[':
				for d.More() {
					if e = visit(); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			default:
				return errors.New("unexpected JSON delimiter")
			}
		}
		return nil
	}
	if e := visit(); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("one JSON value required")
	}
	return nil
}
