package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Categories summarize retained errors, never the potentially sensitive error text.
// They are an explicit diagnostic classifier, not a new execution failure authority.
const operationErrorCategory = `CASE
 WHEN lower(last_error) ~ '(invalid[_ ](pcap|csv)|truncated[_ ](pcap|csv)|pcap.*(invalid|truncated)|csv[_ ](record|header|logical)|parser[_ ]|parse[_ ]error|capture[_ ](truncated|invalid))' THEN 'parse'
 WHEN lower(last_error) ~ '(no space|disk full|enospc|free.disk|host.disk.budget|quota)' THEN 'storage'
 WHEN lower(last_error) ~ '(out.of.memory|oom|memory.limit|pids.limit|timeout|timed out|cpu.limit)' THEN 'resource'
 ELSE 'execution' END`
const operationErrorWhere = `last_error IS NOT NULL AND last_error<>'' AND state IN ('queued','running','failed','cancelling')`

type operationalAlert struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Count    int64  `json:"count,omitempty"`
}
type operationalWorker struct {
	Worker   string    `json:"worker"`
	LastSeen time.Time `json:"last_seen"`
	Kind     string    `json:"last_kind"`
	Age      float64   `json:"age_seconds"`
	Online   bool      `json:"online"`
}
type operationalQueue struct {
	Eligible           int64   `json:"eligible"`
	Delayed            int64   `json:"delayed"`
	Running            int64   `json:"running"`
	OldestWait         float64 `json:"oldest_eligible_wait_seconds"`
	ExpiredLeases      int64   `json:"expired_leases"`
	RetryQueued        int64   `json:"retry_queued"`
	RetriedJobs        int64   `json:"retried_jobs"`
	AdditionalAttempts int64   `json:"additional_attempts"`
}
type operationalError struct {
	Job      string `json:"run_id"`
	State    string `json:"state"`
	Attempt  int    `json:"attempt"`
	Category string `json:"category"`
}

func boundedOperationInt(r *http.Request, name string, def, min, max int) (int, error) {
	raw, ok := r.URL.Query()[name]
	if !ok {
		return def, nil
	}
	if len(raw) != 1 {
		return 0, fmt.Errorf("duplicate query")
	}
	value, err := strconv.Atoi(raw[0])
	if err != nil || value < min || value > max {
		return 0, fmt.Errorf("query outside bounds")
	}
	return value, nil
}
func (s *Server) serveOperations(w http.ResponseWriter, r *http.Request, p *principal, parts []string) {
	if len(parts) != 2 || parts[1] != "operations" {
		fail(w, 404, "not_found", "route not found")
		return
	}
	if p.Role != "admin" {
		fail(w, 403, "forbidden", "administrator access required")
		return
	}
	if r.Method != "GET" {
		fail(w, 405, "method_not_allowed", "operations query requires GET")
		return
	}
	allowed := map[string]bool{"limit": true, "offset": true, "errors": true, "worker_stale_seconds": true, "queue_warn_seconds": true}
	for name, values := range r.URL.Query() {
		if !allowed[name] || len(values) != 1 {
			fail(w, 422, "invalid_query", "unknown or repeated operations query")
			return
		}
	}
	limit, e1 := boundedOperationInt(r, "limit", 20, 1, 100)
	offset, e2 := boundedOperationInt(r, "offset", 0, 0, 1000000)
	stale, e3 := boundedOperationInt(r, "worker_stale_seconds", 120, 2, 3600)
	queueWarn, e4 := boundedOperationInt(r, "queue_warn_seconds", 60, 1, 86400)
	category := r.URL.Query().Get("errors")
	if category == "" {
		category = "all"
	}
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !(category == "all" || category == "parse" || category == "storage" || category == "resource" || category == "execution") {
		fail(w, 422, "invalid_query", "operations query outside declared bounds")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var schema bool
	if err := s.DB.QueryRowContext(ctx, `SELECT to_regclass('m4_worker_observations') IS NOT NULL`).Scan(&schema); err != nil {
		fail(w, 503, "operations_unavailable", "operational database query unavailable")
		return
	}
	if !schema {
		fail(w, 503, "operations_schema_not_ready", "apply worker observation migration before operational queries")
		return
	}
	q, workers, totalWorkers, fresh, missingHeartbeat, counts, events, total, err := s.readOperations(ctx, limit, offset, stale, category)
	if err != nil {
		fail(w, 503, "operations_unavailable", "bounded operational query unavailable")
		return
	}
	stores := s.storageHealth()
	alerts := []operationalAlert{}
	for _, row := range stores {
		if !row.Accessible {
			alerts = append(alerts, operationalAlert{row.Reason, "critical", 1})
		} else if row.FreeBytes < minimumReadyFreeBytes {
			alerts = append(alerts, operationalAlert{"disk_space_low", "critical", 1})
		}
	}
	if q.Eligible > 0 && q.OldestWait >= float64(queueWarn) {
		alerts = append(alerts, operationalAlert{"queue_wait_exceeded", "warning", q.Eligible})
	}
	if q.Eligible > 0 && fresh == 0 {
		alerts = append(alerts, operationalAlert{"workers_unavailable", "critical", q.Eligible})
	}
	if missingHeartbeat > 0 {
		alerts = append(alerts, operationalAlert{"worker_heartbeat_stale", "critical", missingHeartbeat})
	}
	if q.ExpiredLeases > 0 {
		alerts = append(alerts, operationalAlert{"lease_expired", "critical", q.ExpiredLeases})
	}
	if q.RetryQueued > 0 {
		alerts = append(alerts, operationalAlert{"retry_pending", "warning", q.RetryQueued})
	}
	for _, kind := range []string{"parse", "resource", "storage"} {
		if counts[kind] > 0 {
			alerts = append(alerts, operationalAlert{kind + "_failures_recorded", "warning", counts[kind]})
		}
	}
	if reason := s.preparationCoordinatorReason(); reason != "" {
		alerts = append(alerts, operationalAlert{reason, "warning", 1})
	}
	status := "ok"
	if len(alerts) > 0 {
		status = "degraded"
	}
	respond(w, 200, map[string]any{"version": "operations-1", "status": status, "observed_at": time.Now().UTC(), "thresholds": map[string]any{"worker_stale_seconds": stale, "queue_warn_seconds": queueWarn, "disk_low_bytes": minimumReadyFreeBytes}, "queue": q, "workers": workers, "worker_total": totalWorkers, "worker_fresh": fresh, "worker_has_more": int64(len(workers)) < totalWorkers, "storage": stores, "retained_error_counts": counts, "errors": events, "error_page": map[string]any{"offset": offset, "limit": limit, "returned": len(events), "total": total, "has_more": int64(offset+len(events)) < total}, "alerts": alerts, "error_basis": "current retained job last_error classification; not failure event rates; raw reason remains on authorized run status"})
}
func (s *Server) readOperations(ctx context.Context, limit, offset, stale int, category string) (q operationalQueue, workers []operationalWorker, totalWorkers, fresh, missing int64, counts map[string]int64, events []operationalError, total int64, err error) {
	workers = []operationalWorker{}
	events = []operationalError{}
	counts = map[string]int64{}
	err = s.DB.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE state='queued' AND available_at<=clock_timestamp()),count(*) FILTER(WHERE state='queued' AND available_at>clock_timestamp()),count(*) FILTER(WHERE state='running'),coalesce(greatest(extract(epoch FROM clock_timestamp()-min(available_at) FILTER(WHERE state='queued' AND available_at<=clock_timestamp())),0),0)::float8,count(*) FILTER(WHERE state='running' AND lease_until<=clock_timestamp()),count(*) FILTER(WHERE state='queued' AND attempt>0),count(*) FILTER(WHERE attempt>1),coalesce(sum(greatest(attempt-1,0)),0) FROM m4_jobs`).Scan(&q.Eligible, &q.Delayed, &q.Running, &q.OldestWait, &q.ExpiredLeases, &q.RetryQueued, &q.RetriedJobs, &q.AdditionalAttempts)
	if err != nil {
		return
	}
	err = s.DB.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE last_seen>=clock_timestamp()-($1*interval '1 second')) FROM m4_worker_observations`, stale).Scan(&totalWorkers, &fresh)
	if err != nil {
		return
	}
	err = s.DB.QueryRowContext(ctx, `SELECT count(*) FROM m4_jobs j LEFT JOIN m4_worker_observations w ON w.worker=j.worker WHERE j.state='running' AND (w.last_seen IS NULL OR w.last_seen<clock_timestamp()-($1*interval '1 second'))`, stale).Scan(&missing)
	if err != nil {
		return
	}
	var rows *sql.Rows
	rows, err = s.DB.QueryContext(ctx, `SELECT worker,last_seen,last_kind,greatest(extract(epoch FROM clock_timestamp()-last_seen),0)::float8,last_seen>=clock_timestamp()-($1*interval '1 second') FROM m4_worker_observations ORDER BY last_seen DESC,worker LIMIT 100`, stale)
	if err != nil {
		return
	}
	for rows.Next() {
		var row operationalWorker
		if err = rows.Scan(&row.Worker, &row.LastSeen, &row.Kind, &row.Age, &row.Online); err != nil {
			break
		}
		workers = append(workers, row)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return
	}
	rows, err = s.DB.QueryContext(ctx, `SELECT `+operationErrorCategory+`,count(*) FROM m4_jobs WHERE `+operationErrorWhere+` GROUP BY 1`)
	if err != nil {
		return
	}
	for rows.Next() {
		var kind string
		var count int64
		if err = rows.Scan(&kind, &count); err != nil {
			break
		}
		counts[kind] = count
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return
	}
	for kind, count := range counts {
		if category == "all" || category == kind {
			total += count
		}
	}
	rows, err = s.DB.QueryContext(ctx, `SELECT id,state,attempt,`+operationErrorCategory+` FROM m4_jobs WHERE `+operationErrorWhere+` AND ($1='all' OR (`+operationErrorCategory+`)=$1) ORDER BY available_at DESC,id LIMIT $2 OFFSET $3`, category, limit, offset)
	if err != nil {
		return
	}
	for rows.Next() {
		var row operationalError
		if err = rows.Scan(&row.Job, &row.State, &row.Attempt, &row.Category); err != nil {
			break
		}
		events = append(events, row)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	return
}
