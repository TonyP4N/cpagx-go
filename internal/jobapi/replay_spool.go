package jobapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/capacity"
)

const spoolJSONLimit = 8 << 20
const spoolVerification = "source_replayed_storage_and_business_fields_verified"

// Bound host-side replay verification to one Python process in this service.
// Waiting consumes the caller's existing deadline, rather than extending it.
var spoolCLISlot = make(chan struct{}, 1)

type spoolVerified struct {
	Core, Profile, History map[string]any
}

type boundedCLIOutput struct {
	buffer   bytes.Buffer
	maximum  int
	exceeded bool
}

func (w *boundedCLIOutput) Len() int       { return w.buffer.Len() }
func (w *boundedCLIOutput) Bytes() []byte  { return w.buffer.Bytes() }
func (w *boundedCLIOutput) String() string { return w.buffer.String() }

func (w *boundedCLIOutput) Write(p []byte) (int, error) {
	if len(p) > w.maximum-w.Len() {
		w.exceeded = true
		return 0, errors.New("bounded replay bridge output exceeded")
	}
	return w.buffer.Write(p)
}

// Only fixed module/action flags and service-selected paths reach the child.
// No user SQL, module name, command string or unverified artifact path is used.
func (s *Server) spoolCLI(parent context.Context, base, action string, seconds time.Duration, args ...string) (map[string]any, error) {
	switch action {
	case "verify", "metadata", "snapshot", "revisions", "graph", "evidence":
	default:
		return nil, errors.New("unsupported spool bridge action")
	}
	root, err := s.file(strings.TrimSuffix(base, "/"))
	if err != nil {
		return nil, err
	}
	python := s.PythonBin
	if python == "" {
		python = "python3"
	}
	ctx, cancel := context.WithTimeout(parent, seconds)
	defer cancel()
	select {
	case spoolCLISlot <- struct{}{}:
		defer func() { <-spoolCLISlot }()
	case <-ctx.Done():
		return nil, errors.New("replay spool bridge deadline exceeded while queued")
	}
	temporaryBase := ""
	if execution, ok := PreparationExecutionFrom(parent); ok {
		temporaryBase = execution.TemporaryRoot
	} else if s.ControlRoot != "" {
		temporaryBase = filepath.Join(s.ControlRoot, "spool-bridge")
	}
	if temporaryBase != "" {
		if err = os.MkdirAll(temporaryBase, 0700); err != nil {
			return nil, err
		}
		actual, e := filepath.EvalSymlinks(temporaryBase)
		if e != nil || actual != temporaryBase {
			return nil, errors.New("spool bridge temporary root must not contain symlinks")
		}
		info, e := os.Stat(temporaryBase)
		if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("spool bridge temporary root must be private")
		}
	}
	scratch, err := os.MkdirTemp(temporaryBase, "cpag-spool-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)
	argv := []string{"-m", "cpag_core.replay_spool_cli", "--root", root, "--action", action}
	guarded, files, err := GuardPreparationCommand(parent, append(argv, args...))
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, python, guarded...)
	cmd.ExtraFiles = files
	cmd.WaitDelay = time.Second
	cmd.Env = os.Environ()
	pythonPath := s.PythonPath
	if pythonPath == "" {
		pythonPath = filepath.Clean(filepath.Join(dualSchemaDir(), "../services/analysis/src"))
	}
	cmd.Env = append(cmd.Env, "PYTHONPATH="+pythonPath, "PYTHONDONTWRITEBYTECODE=1", "TMPDIR="+scratch)
	if execution, ok := PreparationExecutionFrom(parent); ok {
		cmd.Env = append(cmd.Env, "CPAG_PREPARATION_METRICS="+filepath.Join(execution.TemporaryRoot, "guard.jsonl"))
	}
	stdout, stderr := &boundedCLIOutput{maximum: spoolJSONLimit}, &boundedCLIOutput{maximum: 65536}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err = cmd.Run(); err != nil {
		if stdout.exceeded {
			return nil, errors.New("replay spool bridge output exceeds 8MiB")
		}
		if ctx.Err() != nil {
			return nil, errors.New("replay spool bridge deadline exceeded")
		}
		return nil, fmt.Errorf("replay spool bridge refused: %s", strings.TrimSpace(stderr.String()))
	}
	value, err := parseValue(stdout.Bytes())
	if err != nil {
		return nil, errors.New("replay spool bridge returned invalid JSON")
	}
	object, ok := obj(value)
	if !ok {
		return nil, errors.New("replay spool bridge requires one JSON object")
	}
	return object, nil
}

func (s *Server) spoolInventory(base string, p Payload) error {
	if p.HistoryFormat != ReplaySpoolFormat {
		return errors.New("explicit spool payload required")
	}
	root, err := s.file(strings.TrimSuffix(base, "/"))
	if err != nil {
		return err
	}
	expected := map[string]bool{}
	for _, name := range replayArtifactNamesFor(p) {
		expected[name] = true
	}
	found := map[string]bool{}
	dirs := map[string]bool{}
	var total int64
	budget, err := payloadLimits(p)
	if err != nil {
		return err
	}
	maximum := budget.OutputBytes
	if p.ResourceProfile != "" {
		resource, err := s.artifactLimit(p)
		if err != nil {
			return err
		}
		if resource < maximum {
			maximum = resource
		}
	}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, problem error) error {
		if problem != nil {
			return problem
		}
		if path == root {
			return nil
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("spool inventory symlink forbidden")
		}
		if entry.IsDir() {
			if rel != "sources" && rel != "history" {
				return errors.New("unknown spool directory")
			}
			dirs[rel] = true
			return nil
		}
		info, e := entry.Info()
		if e != nil || !info.Mode().IsRegular() {
			return errors.New("nonregular spool artifact")
		}
		if !expected[rel] && rel != "manifest.json" && !dualAnchor.MatchString(rel) {
			return errors.New("unknown spool artifact")
		}
		if expected[rel] {
			total += info.Size()
			if total > maximum {
				return errors.New("spool aggregate output budget exceeded")
			}
		}
		found[rel] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(dirs) != 2 || !dirs["history"] || !dirs["sources"] {
		return errors.New("spool directory inventory mismatch")
	}
	anchors := 0
	for name := range found {
		if dualAnchor.MatchString(name) {
			anchors++
		}
	}
	if anchors > 1 || (anchors > 0 && !found["manifest.json"]) {
		return errors.New("spool publication anchor inventory mismatch")
	}
	for name := range expected {
		if !found[name] {
			return fmt.Errorf("missing spool artifact: %s", name)
		}
	}
	return nil
}

func (s *Server) validateSpoolReplay(ctx context.Context, base string, p Payload, wrapper Manifest, coreRaw []byte) (*spoolVerified, error) {
	if p.Kind != "dual-source-replay" || p.ReplayVersion != ReplayVersion || p.HistoryFormat != ReplaySpoolFormat {
		return nil, errors.New("spool payload version mismatch")
	}
	if err := s.spoolInventory(base, p); err != nil {
		return nil, err
	}
	coreValue, err := parseValue(coreRaw)
	if err != nil {
		return nil, err
	}
	core, ok := obj(coreValue)
	if !ok {
		return nil, errors.New("spool core manifest object required")
	}
	if err = replaySchema("ReplaySpoolRunManifest", core); err != nil {
		return nil, err
	}
	parts := strings.Split(strings.Trim(base, "/"), "/")
	attempt, _ := intValue(core["attempt_id"])
	if len(parts) != 3 || parts[0] != "jobs" || core["run_id"] != parts[1] || parts[2] != fmt.Sprintf("attempt-%d", attempt) || attempt < 1 || core["replay_version"] != p.ReplayVersion || core["history_format"] != p.HistoryFormat || core["config_fingerprint"] != p.Fingerprint {
		return nil, errors.New("spool run/attempt/profile/format binding mismatch")
	}
	if str(core["capacity_profile"]) != p.CapacityProfile {
		return nil, errors.New("spool core capacity binding mismatch")
	}
	profileValue, err := s.readDualJSON(base, "sources/profile.json", p)
	if err != nil {
		return nil, err
	}
	profile, _ := obj(profileValue)
	if _, err = readPayloadBudget(p, profile); err != nil {
		return nil, err
	}
	if err = validateReplayProfile(profile, p.ReplayVersion); err != nil {
		return nil, err
	}
	_, format, err := replayProfileSchema(profile)
	if err != nil || format != p.HistoryFormat {
		return nil, errors.New("retained spool history format mismatch")
	}
	if core["synthetic"] != profile["synthetic"] {
		return nil, errors.New("spool source category mismatch")
	}
	fp, err := digestValue(profile)
	if err != nil || fp != p.Fingerprint {
		return nil, errors.New("retained spool profile fingerprint mismatch")
	}
	if _, err = s.check(Ref{base + "sources/profile.json", p.Profile.SHA}); err != nil {
		return nil, err
	}
	semanticFP, err := digestValue(replaySemanticProfile(profile))
	if err != nil || semanticFP != core["semantic_config_fingerprint"] {
		return nil, errors.New("spool semantic profile binding mismatch")
	}
	entries, ok := arr(core["artifacts"])
	if !ok {
		return nil, errors.New("spool artifact entries required")
	}
	expected := map[string]bool{}
	for _, name := range replayArtifactNamesFor(p) {
		if name != "run_manifest.json" {
			expected[name] = true
		}
	}
	if len(entries) != len(expected) {
		return nil, errors.New("spool core inventory count mismatch")
	}
	var total int64
	for _, value := range entries {
		entry, yes := obj(value)
		name := str(entry["path"])
		size, valid := intValue(entry["size_bytes"])
		if !yes || !expected[name] || !valid || size < 0 {
			return nil, errors.New("spool core artifact inventory mismatch")
		}
		delete(expected, name)
		n, err := s.checkArtifact(p, Ref{base + name, str(entry["sha256"])})
		if err != nil || n != int64(size) {
			return nil, errors.New("spool core artifact hash/size mismatch")
		}
		total += n
	}
	replay, _ := obj(profile["replay"])
	maximum, valid := intValue(replay["max_output_bytes"])
	if !valid || total+int64(len(coreRaw)) > int64(maximum) {
		return nil, errors.New("spool configured output budget exceeded")
	}
	refs, err := p.networkRefs()
	if err != nil {
		return nil, err
	}
	sourceRows := []any{}
	for i, ref := range append(refs, p.Process) {
		name, kind := networkSourceName(i), "network"
		if i == len(refs) {
			name, kind = "sources/process.csv", "process"
		}
		size, err := s.check(Ref{base + name, ref.SHA})
		if err != nil {
			return nil, err
		}
		original, err := s.check(ref)
		if err != nil || original != size {
			return nil, errors.New("spool retained original source changed")
		}
		sourceRows = append(sourceRows, map[string]any{"kind": kind, "sha256": ref.SHA, "size_bytes": size})
	}
	inputFP, err := digestValue(normalizedJSON(sourceRows))
	if err != nil || inputFP != core["input_fingerprint"] {
		return nil, errors.New("spool original input fingerprint mismatch")
	}
	historyValue, err := s.readDualJSON(base, "history/manifest.json", p)
	if err != nil {
		return nil, err
	}
	history, _ := obj(historyValue)
	if err = replaySchema("ReplayHistorySpoolManifest", history); err != nil {
		return nil, err
	}
	if _, err = s.check(Ref{base + "history/manifest.json", str(core["history_manifest_sha256"])}); err != nil {
		return nil, err
	}
	context, _ := obj(history["context"])
	if context["run_id"] != core["run_id"] || !sameJSON(context["attempt_id"], core["attempt_id"]) || context["replay_version"] != p.ReplayVersion || context["semantic_config_fingerprint"] != semanticFP || history["version"] != p.HistoryFormat {
		return nil, errors.New("spool history context binding mismatch")
	}
	seconds := 180 * time.Second
	if p.ResourceProfile == capacity.Engineering {
		seconds = 600 * time.Second
	}
	verified, err := s.spoolCLI(ctx, base, "verify", seconds)
	if err != nil {
		return nil, err
	}
	verifiedHistory, _ := obj(verified["history"])
	if verified["verification"] != spoolVerification || verified["history_format"] != p.HistoryFormat || !sameJSON(verified["manifest"], core) || !sameJSON(verifiedHistory["manifest"], history) || verifiedHistory["manifest_sha256"] != core["history_manifest_sha256"] {
		return nil, errors.New("spool source replay verification binding mismatch")
	}
	_ = wrapper // Wrapper artifact hashes/attempt identity are checked by caller.
	return &spoolVerified{Core: core, Profile: profile, History: history}, nil
}

var spoolSelector = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)

func (s *Server) serveSpoolReplay(w http.ResponseWriter, r *http.Request, base string, p Payload, kind string) error {
	budget, err := payloadLimits(p)
	if err != nil {
		return err
	}
	if kind == "replay-result" && !r.URL.Query().Has("revision") {
		values := map[string]any{}
		for _, name := range []string{"analysis", "graph", "events", "quality", "replay"} {
			value, err := s.readDualJSON(base, name+".json", p)
			if err != nil {
				return err
			}
			values[name] = value
		}
		analysis, _ := obj(values["analysis"])
		reply(w, 200, map[string]any{"mode": "dual_source_replay", "replay_version": p.ReplayVersion, "history_format": p.HistoryFormat, "synthetic": analysis["synthetic"], "revision": nil, "data": values})
		return nil
	}
	args := []string{}
	action := "snapshot"
	if kind == "replay-revisions" {
		after, err := replayQueryInt(r, "after", 0, 0, budget.Revisions)
		if err != nil {
			return err
		}
		limit, err := replayQueryInt(r, "limit", 100, 1, 100)
		if err != nil {
			return err
		}
		action = "revisions"
		args = []string{"--after", fmt.Sprint(after), "--limit", fmt.Sprint(limit)}
	} else {
		n, err := replayQueryInt(r, "revision", -1, 0, budget.Snapshots-1)
		if err != nil || n < 0 {
			return errors.New("explicit bounded spool snapshot required")
		}
		args = []string{"--snapshot", fmt.Sprint(n)}
		if kind == "replay-evidence" {
			action = "evidence"
			selectors := 0
			for _, key := range []string{"operation", "change"} {
				value := r.URL.Query().Get(key)
				if value != "" {
					if !spoolSelector.MatchString(value) {
						return errors.New("invalid spool evidence selector")
					}
					selectors++
					args = append(args, "--"+key, value)
				}
			}
			if value, present := r.URL.Query()["trigger"]; present {
				if len(value) != 1 || value[0] != "true" {
					return errors.New("spool trigger must be exactly true")
				}
				selectors++
				args = append(args, "--trigger")
			}
			if selectors != 1 {
				return errors.New("select exactly one spool operation, change or trigger")
			}
			for _, key := range []string{"ref_offset", "ref_limit"} {
				if values, present := r.URL.Query()[key]; present && (len(values) != 1 || values[0] == "") {
					return errors.New("one nonempty spool evidence page value required")
				}
			}
			offset, err := replayQueryInt(r, "ref_offset", 0, 0, budget.Frames+budget.ProcessRecords*budget.ProcessColumns)
			if err != nil {
				return err
			}
			limit, err := replayQueryInt(r, "ref_limit", 100, 1, 100)
			if err != nil {
				return err
			}
			args = append(args, "--ref-offset", fmt.Sprint(offset), "--ref-limit", fmt.Sprint(limit))
		} else if kind != "replay-result" && kind != "replay-snapshot" {
			return errors.New("unknown spool projection")
		}
	}
	value, err := s.spoolCLI(r.Context(), base, action, 10*time.Second, args...)
	if err != nil {
		return err
	}
	if kind == "replay-result" {
		analysis, _ := obj(value["analysis"])
		reply(w, 200, map[string]any{"mode": "dual_source_replay", "replay_version": p.ReplayVersion, "history_format": p.HistoryFormat, "synthetic": analysis["synthetic"], "revision": value["snapshot_number"], "data": map[string]any{"analysis": analysis, "graph": value["graph"], "events": value["events"], "quality": analysis["quality"]}})
		return nil
	}
	reply(w, 200, value)
	return nil
}

var _ io.Writer = (*boundedCLIOutput)(nil)
