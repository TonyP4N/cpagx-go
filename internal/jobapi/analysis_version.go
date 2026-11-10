package jobapi

import "errors"

const currentBoundedAnalysisVersion = "bounded-dual-source-2"
const historicalBoundedAnalysisVersion = "bounded-dual-source-1"

// dualAnalysisVersion selects only a retained, explicitly supported version.
// The caller also checks the same version on the retained analysis. Historical
// manifests bind that value through their artifact hashes, without rewriting it.
func dualAnalysisVersion(profile map[string]any, retained any) (string, error) {
	version, ok := retained.(string)
	if !ok {
		return "", errors.New("missing dual analysis version")
	}
	if profile["analysis_mode"] == "bounded-real-capable-v1" {
		if version == historicalBoundedAnalysisVersion || version == currentBoundedAnalysisVersion {
			return version, nil
		}
		return "", errors.New("unsupported bounded dual analysis version")
	}
	if version != "synthetic-dual-source-1" {
		return "", errors.New("unsupported legacy dual analysis version")
	}
	return version, nil
}

// Old completed publications remain idempotent; new executions must use the
// fixed response-clock semantics. No retained artifact or job state is changed.
func validateDualPublicationVersion(version string, completed bool) error {
	switch version {
	case "synthetic-dual-source-1", currentBoundedAnalysisVersion:
		return nil
	case historicalBoundedAnalysisVersion:
		if completed {
			return nil
		}
		return errors.New("historical bounded analysis cannot be newly published; reanalysis required")
	default:
		return errors.New("unsupported dual analysis version")
	}
}

func addDualCompatibility(response, analysis map[string]any) {
	if analysis["analysis_version"] == historicalBoundedAnalysisVersion {
		response["compatibility"] = map[string]any{"analysis_version": historicalBoundedAnalysisVersion, "status": "historical_semantics", "known_limitations": []string{"response_clock_quality_not_enforced"}, "reanalysis_required": true}
	}
}
