"""Validate observed Kubernetes execution identity before recording termination.

The caller must fetch both objects from the trusted API. This observation is
not a publication permit and does not establish foreground deletion.
"""
def termination(job, pods, *, job_uid, run_id, attempt, worker):
    meta = job["metadata"]
    labels = {"cpag.job": run_id, "cpag.attempt": str(attempt), "cpag.worker": worker}
    if not job_uid or meta["uid"] != job_uid or not labels.items() <= meta["labels"].items():
        raise ValueError("job identity mismatch")
    spec = job["spec"]
    if spec.get("backoffLimit") != 0 or spec.get("parallelism", 1) != 1 or spec.get("completions", 1) != 1:
        raise ValueError("ambiguous execution multiplicity")
    if len(pods) != 1:
        raise ValueError("one observed execution pod required")
    pod = pods[0]
    pm = pod["metadata"]
    owners = [r for r in pm["ownerReferences"] if r.get("controller")]
    if len(owners) != 1 or owners[0]["uid"] != job_uid or owners[0]["kind"] != "Job" or pm["namespace"] != meta["namespace"]:
        raise ValueError("pod owner mismatch")
    if not labels.items() <= pm["labels"].items():
        raise ValueError("pod execution labels mismatch")
    statuses = pod["status"].get("containerStatuses", [])
    if pod["status"].get("phase") not in ("Succeeded", "Failed") or len(statuses) != 1:
        raise ValueError("execution termination pending")
    s = statuses[0]
    end = s["state"].get("terminated", {})
    if s["name"] != "compute" or s["restartCount"] != 0 or not end.get("finishedAt") or not s.get("containerID") or end.get("containerID") != s["containerID"] or type(end.get("exitCode")) is not int:
        raise ValueError("missing unambiguous runtime termination evidence")
    return {"version": "kubernetes-termination-1", "run_id": run_id, "attempt": attempt,
            "worker": worker, "namespace": pm["namespace"], "job_uid": job_uid,
            "pod_uid": pm["uid"], "container_id": s["containerID"],
            "finished_at": end["finishedAt"], "exit_code": end["exitCode"]}
