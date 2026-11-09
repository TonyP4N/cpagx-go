package jobs

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// ResidentExecution binds the trusted guardian receipt to a registered runtime.
// The computation never receives the coordinator credential or control volume.
type ResidentExecution struct {
	Reason        string    `json:"reason,omitempty"`
	Version       string    `json:"version"`
	Namespace     string    `json:"namespace"`
	PodName       string    `json:"pod_name"`
	PodUID        string    `json:"pod_uid"`
	ContainerName string    `json:"container_name"`
	ContainerID   string    `json:"container_id"`
	GroupExited   bool      `json:"group_exited,omitempty"`
	ChildPID      int       `json:"child_pid,omitempty"`
	GuardianPID   int       `json:"guardian_pid,omitempty"`
	ReturnCode    *int      `json:"returncode,omitempty"`
	FinishedAt    time.Time `json:"finished_at,omitempty"`
}

var kubeName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

func residentLocation(location string) bool {
	uid, ok := strings.CutPrefix(location, "resident:")
	return ok && kubeUID.MatchString(uid)
}
func validResidentIdentity(p ResidentExecution) bool {
	raw, ok := strings.CutPrefix(p.ContainerID, "containerd://")
	return p.Namespace == "cpag" && kubeUID.MatchString(p.PodUID) && len(p.PodName) <= 253 && kubeName.MatchString(p.PodName) && len(p.ContainerName) <= 63 && kubeName.MatchString(p.ContainerName) && ok && digest.MatchString(raw)
}
func sameResident(a, b ResidentExecution) bool {
	return a.Namespace == b.Namespace && a.PodName == b.PodName && a.PodUID == b.PodUID && a.ContainerName == b.ContainerName && a.ContainerID == b.ContainerID
}
func validResidentExit(c Claim, p ExitProof, recovered bool) bool {
	k := p.Resident
	if k == nil || !validResidentIdentity(*k) || !residentLocation(p.Location) || p.Scope != "resident-process-group" || !p.Exited || p.ContainerID != k.ContainerID || p.ID != c.ID || p.Attempt != c.Attempt || p.Worker != c.Worker || c.Token == "" || p.Token != c.Token {
		return false
	}
	if recovered {
		return k.Version == "resident-container-terminated-1" && !k.FinishedAt.IsZero() && k.ReturnCode != nil
	}
	return k.Version == "resident-guardian-1" && k.GroupExited && k.ChildPID > 0 && k.GuardianPID > 0 && k.ChildPID != k.GuardianPID && k.ReturnCode != nil
}
func (r Repository) RegisterResidentExecution(ctx context.Context, c Claim, location, containerID string, p ResidentExecution) error {
	return r.registerExecution(ctx, c, location, containerID, &p)
}
func (r Repository) recordResidentExit(ctx context.Context, c Claim, p ExitProof, recovered bool) error {
	if !recovered {
		if r.ControlRoot == "" {
			return ErrInvalidProof
		}
		trusted, err := readExit(r.ControlRoot, c)
		if err != nil {
			return fmt.Errorf("%w: trusted guardian file unavailable", ErrInvalidProof)
		}
		a, _ := json.Marshal(trusted)
		b, _ := json.Marshal(p)
		if !bytes.Equal(a, b) {
			return fmt.Errorf("%w: trusted guardian file mismatch", ErrInvalidProof)
		}
	}
	if !validResidentExit(c, p, recovered) {
		return ErrInvalidProof
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var locked string
	if err = tx.QueryRowContext(ctx, `SELECT id FROM m4_jobs WHERE id=$1 FOR UPDATE`, c.ID).Scan(&locked); err != nil {
		return err
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT resident_execution FROM m4_job_attempts WHERE job_id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND executor_kind='resident-v1' AND location=$5 AND container_id=$6`, c.ID, c.Attempt, c.Worker, c.Token, p.Location, p.ContainerID).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrStale
		}
		return err
	}
	var registered ResidentExecution
	if json.Unmarshal(raw, &registered) != nil || !sameResident(registered, *p.Resident) {
		return ErrInvalidProof
	}
	receipt, _ := json.Marshal(p)
	result, err := tx.ExecContext(ctx, `UPDATE m4_job_attempts SET exited_at=coalesce(exited_at,clock_timestamp()),exit_checked_at=clock_timestamp(),exit_error=NULL,exit_receipt=coalesce(exit_receipt,$5::jsonb) WHERE job_id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND (exit_receipt IS NULL OR exit_receipt=$5::jsonb)`, c.ID, c.Attempt, c.Worker, c.Token, string(receipt))
	if err = affected(result, err); err != nil {
		return err
	}
	return tx.Commit()
}

// terminatedResident matches only the exact registered container, including the
// previous incarnation after a restart. A missing Pod or status is never evidence.
func terminatedResident(raw []byte, registered ResidentExecution) (ResidentExecution, error) {
	var pod struct {
		Metadata struct {
			UID       string `json:"uid"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Status struct {
			Containers []struct {
				Name  string `json:"name"`
				State struct {
					Terminated *residentTermination `json:"terminated"`
				} `json:"state"`
				LastState struct {
					Terminated *residentTermination `json:"terminated"`
				} `json:"lastState"`
			} `json:"containerStatuses"`
		} `json:"status"`
	}
	if json.Unmarshal(raw, &pod) != nil || pod.Metadata.UID != registered.PodUID || pod.Metadata.Name != registered.PodName || pod.Metadata.Namespace != registered.Namespace {
		return ResidentExecution{}, ErrInvalidProof
	}
	for _, c := range pod.Status.Containers {
		if c.Name != registered.ContainerName {
			continue
		}
		for _, t := range []*residentTermination{c.State.Terminated, c.LastState.Terminated} {
			if t != nil && t.ContainerID == registered.ContainerID && t.ExitCode != nil && !t.FinishedAt.IsZero() {
				p := registered
				p.Version = "resident-container-terminated-1"
				p.ReturnCode = t.ExitCode
				p.FinishedAt = t.FinishedAt
				return p, nil
			}
		}
	}
	return ResidentExecution{}, fmt.Errorf("exact registered resident container termination unavailable")
}

type residentTermination struct {
	ContainerID string    `json:"containerID"`
	ExitCode    *int      `json:"exitCode"`
	FinishedAt  time.Time `json:"finishedAt"`
}

func (r Repository) recoverResident(ctx context.Context, c Claim, location string, p ResidentExecution) error {
	if !validResidentIdentity(p) {
		return ErrInvalidProof
	}
	get := r.PodGet
	if get == nil {
		get = inClusterPodGet
	}
	raw, err := get(ctx, p.Namespace, p.PodName)
	if err != nil {
		return err
	}
	terminated, err := terminatedResident(raw, p)
	if err != nil {
		return err
	}
	return r.recordResidentExit(ctx, c, ExitProof{ID: c.ID, Attempt: c.Attempt, Worker: c.Worker, Token: c.Token, Location: location, ContainerID: p.ContainerID, Scope: "resident-process-group", Exited: true, Resident: &terminated}, true)
}
func inClusterPodGet(ctx context.Context, namespace, name string) ([]byte, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = "443"
	}
	if host == "" {
		return nil, fmt.Errorf("Kubernetes read-only Pod recovery unavailable")
	}
	const base = "/var/run/secrets/kubernetes.io/serviceaccount/"
	token, err := os.ReadFile(base + "token")
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(base + "ca.crt")
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid Kubernetes CA")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.Transport.(*http.Transport).CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+net.JoinHostPort(host, port)+"/api/v1/namespaces/"+url.PathEscape(namespace)+"/pods/"+url.PathEscape(name), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Kubernetes Pod GET status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 2<<20 {
		return nil, fmt.Errorf("Kubernetes Pod too large")
	}
	return raw, nil
}

// Re-read the private final guardian record on every publication attempt. A
// cached coordinator body or previously accepted receipt cannot replace it.
func (r Repository) checkResidentReceipt(ctx context.Context, c Claim) error {
	var executor string
	var raw []byte
	if err := r.DB.QueryRowContext(ctx, `SELECT executor_kind,exit_receipt FROM m4_job_attempts WHERE job_id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4`, c.ID, c.Attempt, c.Worker, c.Token).Scan(&executor, &raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrStale
		}
		return err
	}
	if executor != "resident-v1" {
		return nil
	}
	proof, err := readExit(r.ControlRoot, c)
	if err != nil {
		return ErrInvalidProof
	}
	if !validResidentExit(c, proof, false) || proof.Resident.Reason != "exited" || *proof.Resident.ReturnCode != 0 {
		return ErrInvalidProof
	}
	var stored ExitProof
	if json.Unmarshal(raw, &stored) != nil {
		return ErrInvalidProof
	}
	a, _ := json.Marshal(proof)
	b, _ := json.Marshal(stored)
	if !bytes.Equal(a, b) {
		return ErrInvalidProof
	}
	return nil
}
