package jobapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

var ErrCompactResultChanged = errors.New("compact published result changed")
var ErrCompactSourceVerificationFailed = errors.New("compact source verification failed after controlled exit")
var ErrCompactQueryLimit = errors.New("compact query outside bounded read contract")

// Only typed service failures cross the internal HTTP boundary as public codes.
// Artifact size/digest failures must never be classified from words such as
// "budget" in a diagnostic message.
func CompactErrorCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "query_timeout"
	case errors.Is(err, ErrVerificationPending):
		return "verification_pending"
	case errors.Is(err, ErrCompactResultChanged):
		return "result_changed"
	case errors.Is(err, ErrCompactSourceVerificationFailed):
		return "source_verification_failed"
	case errors.Is(err, ErrCompactQueryLimit):
		return "query_limit"
	}
	return ""
}
func compactHelperError(raw []byte) error {
	var failure struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal(raw, &failure) != nil || failure.Reason == "" {
		return errors.New("compact service helper failed without structured reason")
	}
	reason := strings.SplitN(failure.Reason, ":", 2)[0]
	switch reason {
	case "service_query_deadline", "shared_store_deadline_exceeded":
		return fmt.Errorf("%w: %s", context.DeadlineExceeded, failure.Reason)
	case "service_response_byte_limit", "shared_query_output_limit", "evidence_page_outside_budget", "shared_logical_byte_limit", "shared_page_budget_invalid", "shared_page_byte_limit", "shared_page_requires_array", "shared_selection_path_invalid", "shared_array_index_invalid", "shared_root_page_invalid", "service_query_path_invalid", "service_snapshot_outside_history", "service_unknown_logical_root", "service_query_action_invalid", "select_exactly_one_operation_change_trigger", "offline_snapshot_or_trigger_invalid", "service_replay_required":
		return fmt.Errorf("%w: %s", ErrCompactQueryLimit, failure.Reason)
	case "service_storage_budget_mismatch", "service_exact_inventory_mismatch", "service_publication_sha_mismatch", "service_publication_inventory_mismatch", "service_publication_config_mismatch", "service_publication_binding_mismatch", "service_publication_attempt_mismatch", "service_publication_input_mismatch", "service_publication_network_order_mismatch", "service_publication_history_mismatch", "service_artifact_changed_during_hash", "service_publication_anchor_changed", "service_publication_artifact_changed", "service_verified_bytes_changed", "service_bytes_changed_during_read", "shared_artifact_changed", "shared_inventory_mismatch", "shared_total_physical_limit":
		return fmt.Errorf("%w: %s", ErrCompactResultChanged, failure.Reason)
	default:
		return fmt.Errorf("compact service helper refused: %s", failure.Reason)
	}
}

// Only an explicitly rejected, exited helper is permanent. Control transport,
// cancellation, interrupted execution and unstructured failures remain unknown.
func compactPermanentVerificationFailure(exitError error, exited bool, stderr []byte) error {
	var processExit *exec.ExitError
	if !exited || !errors.As(exitError, &processExit) || processExit.ExitCode() <= 0 {
		return nil
	}
	var failure struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
		Type   string `json:"error_type"`
	}
	if json.Unmarshal(stderr, &failure) != nil || failure.Status != "failed" || failure.Reason == "" {
		return nil
	}
	reason := failure.Reason
	if len(reason) > 768 {
		reason = reason[:768]
	}
	return fmt.Errorf("%w: %s: %s", ErrCompactSourceVerificationFailed, failure.Type, reason)
}
