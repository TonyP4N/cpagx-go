//go:build linux || darwin

package jobs

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Only trusted root supervisors and the API can access this directory. Lock
// availability alone is not termination evidence: a replacement PID1 generation
// of the same singleton must also be active before recovery can settle an exit.
type composeGeneration struct {
	Version    string `json:"version"`
	Deployment string `json:"deployment_id"`
	Generation string `json:"generation"`
	Supervisor string `json:"supervisor_id"`
	PID        int    `json:"pid"`
}

func privateGenerationInfo(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0
}
func generationRoot(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil || root == "" {
		return "", ErrInvalidProof
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || resolved != absolute {
		return "", ErrInvalidProof
	}
	for _, p := range []string{absolute, filepath.Join(absolute, "resident-generations")} {
		info, e := os.Lstat(p)
		if e != nil || !info.IsDir() || !privateGenerationInfo(info) {
			return "", fmt.Errorf("private resident generation directory unavailable")
		}
	}
	return absolute, nil
}
func readGeneration(f *os.File) (composeGeneration, error) {
	var record composeGeneration
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !privateGenerationInfo(info) || info.Size() > 2048 {
		return record, ErrInvalidProof
	}
	b, err := io.ReadAll(io.LimitReader(f, 2049))
	if err != nil || len(b) > 2048 {
		return record, ErrInvalidProof
	}
	if json.Unmarshal(b, &record) != nil || record.Version != "resident-compose-generation-1" || record.PID != 1 || !dispatchIdentity.MatchString(record.Deployment) || !dispatchIdentity.MatchString(record.Generation) || !kubeName.MatchString(record.Supervisor) || len(record.Supervisor) > 63 {
		return record, ErrInvalidProof
	}
	return record, nil
}
func generationMatches(record composeGeneration, p ResidentExecution) bool {
	return record.Deployment == p.DeploymentID && record.Generation == p.Generation && record.Supervisor == p.SupervisorID
}
func readCurrentGeneration(root string) (composeGeneration, error) {
	f, err := os.OpenFile(filepath.Join(root, "resident-current.json"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return composeGeneration{}, ErrInvalidProof
	}
	defer f.Close()
	return readGeneration(f)
}
func observeGenerationLock(root string, p ResidentExecution, held bool) error {
	f, err := os.OpenFile(filepath.Join(root, "resident-generations", p.Generation+".lock"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrInvalidProof
	}
	defer f.Close()
	record, err := readGeneration(f)
	if err != nil || !generationMatches(record, p) {
		return ErrInvalidProof
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		if held {
			return fmt.Errorf("resident PID1 generation is not active")
		}
		return nil
	}
	if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
		if held {
			return nil
		}
		return fmt.Errorf("registered resident PID1 generation is still active")
	}
	return fmt.Errorf("resident generation lock unavailable: %w", err)
}
func verifyComposeRegistration(root string, p ResidentExecution) error {
	root, err := generationRoot(root)
	if err != nil {
		return err
	}
	current, err := readCurrentGeneration(root)
	if err != nil || !generationMatches(current, p) {
		return ErrInvalidProof
	}
	return observeGenerationLock(root, p, true)
}
func verifyComposeTermination(root string, p ResidentExecution) error {
	root, err := generationRoot(root)
	if err != nil {
		return err
	}
	if err = observeGenerationLock(root, p, false); err != nil {
		return err
	}
	current, err := readCurrentGeneration(root)
	if err != nil || current.Generation == p.Generation || current.Deployment != p.DeploymentID || current.Supervisor != p.SupervisorID {
		return fmt.Errorf("replacement resident PID1 generation unavailable")
	}
	replacement := p
	replacement.Generation = current.Generation
	replacement.ContainerID = "pid1://" + current.Generation
	return observeGenerationLock(root, replacement, true)
}
