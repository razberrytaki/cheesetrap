// capacityprobe exercises production paths against explicitly marked synthetic
// fixtures. It is not installed in the runtime image and never creates, ages,
// changes protection states, or executes arbitrary SQL on a fixture.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cheesetrap/internal/detection"
	"cheesetrap/internal/reporting"
	"cheesetrap/internal/retention"
	"cheesetrap/internal/store"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type config struct {
	Action                              string
	Isolated                            bool
	WorkerFile, APIFile, Window, Report string
	Calls                               int
	DiagnosticsDir                      string
}

func (c config) validate() error {
	if err := diagnosticDirectory(c.DiagnosticsDir); err != nil {
		return err
	}
	if !c.Isolated || !filepath.IsAbs(c.WorkerFile) || c.Calls < 1 || c.Calls > 20000 || (c.APIFile != "" && !filepath.IsAbs(c.APIFile)) {
		return errors.New("probe_configuration_invalid")
	}
	switch c.Action {
	case "detect", "cleanup":
	case "draft":
		if !validUUID(c.Window) {
			return errors.New("probe_window_required")
		}
	case "verify":
		if !validUUID(c.Report) {
			return errors.New("probe_report_required")
		}
	case "revise":
		if !validUUID(c.Report) || c.APIFile == "" {
			return errors.New("probe_report_and_api_required")
		}
	default:
		return errors.New("probe_action_invalid")
	}
	return nil
}
func validUUID(s string) bool { var id pgtype.UUID; return id.Scan(s) == nil && id.Valid && s != "" }

func parse(args []string) (config, error) {
	var c config
	fs := flag.NewFlagSet("capacityprobe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.DiagnosticsDir, "diagnostics-dir", "", "existing absolute directory for bounded diagnostic-only memory and heap observations")
	fs.StringVar(&c.Action, "action", "", "detect, draft, revise, cleanup, or verify")
	fs.BoolVar(&c.Isolated, "isolated-fixture", false, "explicit authorization for the marked synthetic fixture")
	fs.StringVar(&c.WorkerFile, "worker-url-file", "", "absolute worker DSN file")
	fs.StringVar(&c.APIFile, "api-url-file", "", "absolute API DSN file (required for revise)")
	fs.StringVar(&c.Window, "window-id", "", "existing fixture window UUID")
	fs.StringVar(&c.Report, "report-id", "", "existing fixture report UUID")
	fs.IntVar(&c.Calls, "calls", 100, "cleanup pass bound, 1..20000 (also bounded by ten minutes)")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return c, errors.New("probe_arguments_invalid")
	}
	return c, c.validate()
}

type copyFingerprint struct {
	Rows   int64  `json:"rows"`
	SHA256 string `json:"sha256"`
}
type snapshot struct {
	Counts           map[string]int64           `json:"counts"`
	Copies           map[string]copyFingerprint `json:"copies_by_report"`
	ProtectedReports map[string]bool            `json:"protected_reports"`
}
type operation struct {
	Name            string  `json:"name"`
	Seconds         float64 `json:"seconds"`
	Deleted         int64   `json:"deleted,omitempty"`
	ProtectedEvents int64   `json:"protected_events,omitempty"`
	Processed       int     `json:"processed,omitempty"`
	DetectedSeq     uint64  `json:"detected_seq,omitempty"`
	More            bool    `json:"more,omitempty"`
	Error           string  `json:"error,omitempty"`
}
type reportValidation struct {
	ReportID             string `json:"report_id"`
	RevisionID           string `json:"revision_id"`
	Version              int64  `json:"version"`
	Evidence             int    `json:"evidence"`
	Rules                int    `json:"rules"`
	ContentDigest        string `json:"content_digest"`
	EvidenceSHA256       string `json:"evidence_sha256"`
	ExactCopies          bool   `json:"exact_copies"`
	BaseProvenance       bool   `json:"base_provenance"`
	BaseProvenanceStatus string `json:"base_provenance_status"`
	BaseEventsAvailable  int64  `json:"base_events_available"`
	ExactRuleMetadata    bool   `json:"exact_rule_metadata"`
}
type result struct {
	Schema                   int                `json:"schema"`
	Action                   string             `json:"action"`
	Status                   string             `json:"status"`
	Error                    string             `json:"error,omitempty"`
	StartedAt                time.Time          `json:"started_at"`
	Seconds                  float64            `json:"seconds"`
	Before                   *snapshot          `json:"before,omitempty"`
	After                    *snapshot          `json:"after,omitempty"`
	Operations               []operation        `json:"operations"`
	Reports                  []reportValidation `json:"reports,omitempty"`
	ProtectedCopiesUnchanged bool               `json:"protected_copies_unchanged"`
	Stopped                  string             `json:"stopped,omitempty"`
}

func main() {
	started := time.Now()
	r := result{Schema: 1, Status: "FAIL", StartedAt: started.UTC(), Operations: []operation{}}
	c, err := parse(os.Args[1:])
	r.Action = c.Action
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		err = run(ctx, c, &r)
		cancel()
	}
	if err != nil {
		r.Error = safeError(err)
	} else {
		r.Status = "PASS"
	}
	r.Seconds = time.Since(started).Seconds()
	_ = json.NewEncoder(os.Stdout).Encode(r)
	if err != nil {
		os.Exit(1)
	}
}
func safeError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, retention.ErrBusy) {
		return "retention_busy"
	}
	// Only fixed harness/application errors reach here; driver errors are never returned.
	switch err.Error() {
	case "probe_diagnostics_directory_invalid", "probe_diagnostics_failed", "probe_configuration_invalid", "probe_window_required", "probe_report_and_api_required", "probe_report_required", "probe_action_invalid", "probe_arguments_invalid", "probe_dsn_file_invalid", "probe_database_connection_failed", "probe_fixture_guard_failed", "probe_database_mismatch", "probe_snapshot_failed", "probe_draft_window_not_first", "probe_window_not_ready", "probe_window_seal_failed", "probe_draft_failed", "probe_draft_no_progress", "probe_draft_call_limit", "probe_detection_failed", "probe_detection_call_limit", "probe_report_read_failed", "probe_report_digest_mismatch", "probe_report_copy_mismatch", "probe_report_base_mismatch", "probe_report_rule_mismatch", "probe_report_revision_failed", "probe_revision_evidence_changed", "probe_cleanup_failed", "probe_protected_copy_changed", "probe_report_list_failed":
		return err.Error()
	default:
		return "probe_failed"
	}
}
func readDSN(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("probe_dsn_file_invalid")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 16384 {
		return "", errors.New("probe_dsn_file_invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 || strings.TrimSpace(string(raw)) == "" {
		return "", errors.New("probe_dsn_file_invalid")
	}
	return strings.TrimSpace(string(raw)), nil
}
func openPool(ctx context.Context, path string, diagnostics *probeDiagnostics) (*pgxpool.Pool, error) {
	dsn, err := readDSN(path)
	if err != nil {
		return nil, err
	}
	p, err := store.NewPool(ctx, dsn)
	if err != nil {
		return nil, errors.New("probe_database_connection_failed")
	}
	if diagnostics != nil {
		cfg := p.Config()
		p.Close()
		cfg.ConnConfig.Tracer = diagnostics
		connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		p, err = pgxpool.NewWithConfig(connectCtx, cfg)
		if err == nil {
			err = p.Ping(connectCtx)
		}
		if err != nil {
			if p != nil {
				p.Close()
			}
			return nil, errors.New("probe_database_connection_failed")
		}
	}
	return p, nil
}
func phase(name, event string) {
	_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"phase": name, "event": event, "at": time.Now().UTC()})
}

func checkGuard(marker string, unsafeEvents, unsafeCopies int64) error {
	if marker != "isolated-v1" || unsafeEvents != 0 || unsafeCopies != 0 {
		return errors.New("probe_fixture_guard_failed")
	}
	return nil
}
func guard(ctx context.Context, p *pgxpool.Pool) error {
	var marker string
	var badEvents, badCopies int64
	err := p.QueryRow(ctx, `SELECT coalesce(current_setting('cheesetrap.capacity_fixture',true),''),
 (SELECT count(*) FROM cheesetrap.events WHERE is_test IS DISTINCT FROM true),
 (SELECT count(*) FROM cheesetrap.report_evidence WHERE snapshot->>'is_test' IS DISTINCT FROM 'true')`).Scan(&marker, &badEvents, &badCopies)
	if err != nil {
		return errors.New("probe_fixture_guard_failed")
	}
	return checkGuard(marker, badEvents, badCopies)
}
func sameDatabase(a, b *pgxpool.Pool) bool {
	x, y := a.Config().ConnConfig, b.Config().ConnConfig
	return x.Host == y.Host && x.Port == y.Port && x.Database == y.Database
}
func run(ctx context.Context, c config, r *result) (runErr error) {
	diagnostics, err := startDiagnostics(ctx, c.DiagnosticsDir)
	if err != nil {
		return err
	}
	if diagnostics != nil {
		defer func() {
			if closeErr := diagnostics.Close(); runErr == nil {
				runErr = closeErr
			}
		}()
	}
	worker, err := openPool(ctx, c.WorkerFile, diagnostics)
	if err != nil {
		return err
	}
	defer worker.Close()
	if err = guard(ctx, worker); err != nil {
		return err
	}
	api := worker
	if c.APIFile != "" {
		api, err = openPool(ctx, c.APIFile, diagnostics)
		if err != nil {
			return err
		}
		defer api.Close()
		if !sameDatabase(worker, api) {
			return errors.New("probe_database_mismatch")
		}
		if err = guard(ctx, api); err != nil {
			return err
		}
	}
	phase("before_snapshot", "start")
	before, err := capture(ctx, worker)
	if err != nil {
		return err
	}
	r.Before = &before
	phase("before_snapshot", "complete")
	switch c.Action {
	case "detect":
		err = detect(ctx, worker, r)
	case "draft":
		err = draft(ctx, worker, api, c.Window, r)
	case "revise":
		err = revise(ctx, worker, api, c.Report, r)
	case "verify":
		var v reportValidation
		v, err = validateReport(ctx, worker, c.Report, false)
		r.Reports = append(r.Reports, v)
		r.Stopped = "verification_only"
	case "cleanup":
		r.Operations, err = cleanupPasses(ctx, c.Calls, func(passCtx context.Context) (retention.Progress, error) {
			if e := guard(passCtx, worker); e != nil {
				return retention.Progress{}, e
			}
			p, e := retention.Cleanup(passCtx, worker, time.Now().UTC(), 100)
			if e != nil && !errors.Is(e, retention.ErrBusy) && !errors.Is(e, context.DeadlineExceeded) && !errors.Is(e, context.Canceled) {
				e = errors.New("probe_cleanup_failed")
			}
			return p, e
		})
		if err == nil {
			r.Stopped = "call_limit"
			if len(r.Operations) > 0 && r.Operations[len(r.Operations)-1].Deleted == 0 {
				r.Stopped = "no_progress"
			}
		}
	}
	// Preserve a final read-only observation even when the operation's deadline failed.
	finalCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	phase("after_snapshot", "start")
	after, captureErr := capture(finalCtx, worker)
	if captureErr == nil {
		phase("after_snapshot", "complete")
		r.After = &after
		r.ProtectedCopiesUnchanged = protectedUnchanged(before, after)
		if !r.ProtectedCopiesUnchanged && err == nil {
			err = errors.New("probe_protected_copy_changed")
		}
	}
	if err != nil {
		return err
	}
	return captureErr
}

func capture(ctx context.Context, p *pgxpool.Pool) (snapshot, error) {
	s := snapshot{Counts: map[string]int64{}, Copies: map[string]copyFingerprint{}, ProtectedReports: map[string]bool{}}
	rows, err := p.Query(ctx, `SELECT 'events',count(*) FROM cheesetrap.events
 UNION ALL SELECT 'detection_completions',count(*) FROM cheesetrap.detection_completions
 UNION ALL SELECT 'detection_results',count(*) FROM cheesetrap.detection_results
 UNION ALL SELECT 'retiring_results',count(*) FROM cheesetrap.detection_results WHERE evidence_state='retiring'
 UNION ALL SELECT 'legacy_links',count(*) FROM cheesetrap.detection_evidence
 UNION ALL SELECT 'chunk_references',count(*) FROM cheesetrap.detection_evidence_chunks
 UNION ALL SELECT 'chunk_members',count(*) FROM cheesetrap.evidence_chunk_members
 UNION ALL SELECT 'chunk_headers',count(*) FROM cheesetrap.evidence_chunks
 UNION ALL SELECT 'reports',count(*) FROM cheesetrap.reports
 UNION ALL SELECT 'report_evidence',count(*) FROM cheesetrap.report_evidence
 UNION ALL SELECT 'report_revisions',count(*) FROM cheesetrap.report_revisions
 UNION ALL SELECT 'completed_windows',count(*) FROM cheesetrap.report_window_completions
 UNION ALL SELECT 'ingested_seq',ingested_seq FROM cheesetrap.processing_cursors
 UNION ALL SELECT 'detected_seq',detected_seq FROM cheesetrap.processing_cursors`)
	if err != nil {
		return s, errors.New("probe_snapshot_failed")
	}
	for rows.Next() {
		var k string
		var n int64
		if rows.Scan(&k, &n) != nil {
			rows.Close()
			return s, errors.New("probe_snapshot_failed")
		}
		s.Counts[k] = n
	}
	rows.Close()
	if rows.Err() != nil {
		return s, errors.New("probe_snapshot_failed")
	}
	rows, err = p.Query(ctx, `SELECT report_id::text,NOT(last_changed_at<clock_timestamp()-interval '180 days' AND (state='closed_unconfirmed' OR(state IN('sent','rejected') AND NOT delivery_uncertain)) AND active_refresh_id IS NULL) FROM cheesetrap.reports ORDER BY report_id`)
	if err != nil {
		return s, errors.New("probe_snapshot_failed")
	}
	for rows.Next() {
		var id string
		var protected bool
		if rows.Scan(&id, &protected) != nil {
			rows.Close()
			return s, errors.New("probe_snapshot_failed")
		}
		s.ProtectedReports[id] = protected
		s.Copies[id] = copyFingerprint{SHA256: hex.EncodeToString(sha256.New().Sum(nil))}
	}
	rows.Close()
	if rows.Err() != nil {
		return s, errors.New("probe_snapshot_failed")
	}
	rows, err = p.Query(ctx, `SELECT report_id::text,event_id::text,snapshot::text FROM cheesetrap.report_evidence ORDER BY report_id,event_id`)
	if err != nil {
		return s, errors.New("probe_snapshot_failed")
	}
	current := ""
	var h hash.Hash
	var n int64
	finish := func() {
		if current != "" {
			s.Copies[current] = copyFingerprint{Rows: n, SHA256: hex.EncodeToString(h.Sum(nil))}
		}
	}
	for rows.Next() {
		var id, event, payload string
		if rows.Scan(&id, &event, &payload) != nil {
			rows.Close()
			return s, errors.New("probe_snapshot_failed")
		}
		if id != current {
			finish()
			current = id
			h = sha256.New()
			n = 0
		}
		fmt.Fprintf(h, "%d:%s%d:%s", len(event), event, len(payload), payload)
		n++
	}
	finish()
	rows.Close()
	if rows.Err() != nil {
		return s, errors.New("probe_snapshot_failed")
	}
	return s, nil
}
func protectedUnchanged(before, after snapshot) bool {
	for id, protected := range before.ProtectedReports {
		if protected {
			got, ok := after.Copies[id]
			if !ok || got != before.Copies[id] {
				return false
			}
		}
	}
	return true
}

func detect(parent context.Context, p *pgxpool.Pool, r *result) error {
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	for i := 0; i < 10000; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := guard(ctx, p); err != nil {
			return err
		}
		callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
		started := time.Now()
		phase("detect", "start")
		progress, err := detection.ProcessBatchWithBudget(callCtx, p, 1000, time.Second)
		phase("detect", "returned")
		o := operation{Name: "detect", Seconds: time.Since(started).Seconds(), Processed: progress.Processed, DetectedSeq: progress.DetectedSeq, More: progress.HasMore}
		stop()
		if err != nil {
			o.Error = "probe_detection_failed"
			r.Operations = append(r.Operations, o)
			return errors.New("probe_detection_failed")
		}
		r.Operations = append(r.Operations, o)
		if !progress.HasMore {
			r.Stopped = "cursor_caught_up"
			return nil
		}
	}
	return errors.New("probe_detection_call_limit")
}
func draft(ctx context.Context, p, reader *pgxpool.Pool, window string, r *result) error {
	if err := guard(ctx, p); err != nil {
		return err
	}
	var earliest string
	if p.QueryRow(ctx, `SELECT window_id::text FROM cheesetrap.report_windows w WHERE NOT EXISTS(SELECT 1 FROM cheesetrap.report_window_completions c WHERE c.window_id=w.window_id) ORDER BY start_at LIMIT 1`).Scan(&earliest) != nil || earliest != window {
		return errors.New("probe_draft_window_not_first")
	}
	callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	started := time.Now()
	phase("seal_window", "start")
	ready, err := reporting.SealWindow(callCtx, p, window)
	phase("seal_window", "returned")
	cancel()
	o := operation{Name: "seal_window", Seconds: time.Since(started).Seconds()}
	if err != nil {
		o.Error = "probe_window_seal_failed"
	}
	r.Operations = append(r.Operations, o)
	if err != nil {
		return errors.New("probe_window_seal_failed")
	}
	if !ready {
		return errors.New("probe_window_not_ready")
	}
	svc := reporting.NewDraftService(p)
	for i := 0; i < 100; i++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = guard(ctx, p); err != nil {
			return err
		}
		var complete bool
		if p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap.report_window_completions WHERE window_id=$1)`, window).Scan(&complete) != nil {
			return errors.New("probe_draft_failed")
		}
		if complete {
			r.Stopped = "window_completed"
			return validateWindow(ctx, p, reader, window, r)
		}
		// Never let Next cross into a different window during this targeted probe.
		if p.QueryRow(ctx, `SELECT window_id::text FROM cheesetrap.report_windows w WHERE NOT EXISTS(SELECT 1 FROM cheesetrap.report_window_completions c WHERE c.window_id=w.window_id) ORDER BY start_at LIMIT 1`).Scan(&earliest) != nil || earliest != window {
			return errors.New("probe_draft_window_not_first")
		}
		callCtx, cancel = context.WithTimeout(ctx, 60*time.Second)
		started = time.Now()
		phase("draft", "start")
		progress, e := svc.Next(callCtx)
		phase("draft", "returned")
		cancel()
		o = operation{Name: "draft", Seconds: time.Since(started).Seconds(), More: progress.More}
		if progress.Processed {
			o.Processed = 1
		}
		if e != nil {
			o.Error = "probe_draft_failed"
		}
		r.Operations = append(r.Operations, o)
		if e != nil {
			return errors.New("probe_draft_failed")
		}
		if !progress.Processed {
			return errors.New("probe_draft_no_progress")
		}
	}
	var complete bool
	if p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap.report_window_completions WHERE window_id=$1)`, window).Scan(&complete) == nil && complete {
		r.Stopped = "window_completed"
		return validateWindow(ctx, p, reader, window, r)
	}
	return errors.New("probe_draft_call_limit")
}
func validateWindow(ctx context.Context, p, reader *pgxpool.Pool, window string, r *result) error {
	rows, err := p.Query(ctx, `SELECT report_id::text FROM cheesetrap.reports WHERE window_id=$1 ORDER BY report_id`, window)
	if err != nil {
		return errors.New("probe_report_list_failed")
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return errors.New("probe_report_list_failed")
		}
		ids = append(ids, id)
	}
	rows.Close()
	if rows.Err() != nil {
		return errors.New("probe_report_list_failed")
	}
	for _, id := range ids {
		v, e := validateReport(ctx, reader, id, true)
		r.Reports = append(r.Reports, v)
		if e != nil {
			return e
		}
	}
	return nil
}
func validateReport(ctx context.Context, p *pgxpool.Pool, id string, base bool) (reportValidation, error) {
	phase("validate_report", "start")
	phase("validate_load", "start")
	r, err := reporting.LoadRevision(ctx, p, id)
	phase("validate_load", "returned")
	if err != nil {
		return reportValidation{}, errors.New("probe_report_read_failed")
	}
	v := reportValidation{ReportID: id, RevisionID: r.RevisionID, Version: r.Version, Evidence: len(r.Snapshot.Evidence), Rules: len(r.Snapshot.Rules), ContentDigest: r.ContentDigest}
	phase("validate_digest", "start")
	digest, err := reporting.ContentDigest(r)
	phase("validate_digest", "returned")
	if err != nil || digest != r.ContentDigest {
		return v, errors.New("probe_report_digest_mismatch")
	}
	phase("validate_evidence_hash", "start")
	v.EvidenceSHA256, err = evidenceSHA256(r.Snapshot.Evidence)
	phase("validate_evidence_hash", "returned")
	if err != nil {
		return v, errors.New("probe_report_read_failed")
	}
	phase("validate_copies", "start")
	err = verifyRevisionCopies(ctx, p, id, v.RevisionID, v.Evidence)
	phase("validate_copies", "returned")
	if err != nil {
		return v, err
	}
	v.ExactCopies = true
	var mismatches int64
	phase("validate_provenance", "start")
	err = p.QueryRow(ctx, `SELECT count(*) FILTER (WHERE e.event_id IS NOT NULL),
 count(*) FILTER (WHERE e.event_id IS NOT NULL AND (NOT(re.snapshot @> jsonb_build_object(
   'event_id',e.event_id::text,'ingestion_seq',e.ingestion_seq,'sensor_id',e.sensor_id::text,'engine',e.engine,
   'source_ip',coalesce(host(e.source_ip),''),'source_port',coalesce(e.source_port,0),
   'destination_ip',coalesce(host(e.destination_ip),''),'destination_port',coalesce(e.destination_port,0),
   'service',e.service,'event_type',e.event_type,'raw_hash',e.raw_hash,'is_test',e.is_test))
   OR (re.snapshot->>'ingested_at')::timestamptz IS DISTINCT FROM e.ingested_at
   OR (re.snapshot->>'observed_at')::timestamptz IS DISTINCT FROM coalesce(e.observed_at,'0001-01-01T00:00:00Z'::timestamptz)))
 FROM cheesetrap.report_evidence re LEFT JOIN cheesetrap.events e USING(event_id) WHERE re.report_id=$1`, id).Scan(&v.BaseEventsAvailable, &mismatches)
	phase("validate_provenance", "returned")
	if err != nil || mismatches != 0 {
		v.BaseProvenanceStatus = "mismatch"
		return v, errors.New("probe_report_base_mismatch")
	}
	v.BaseProvenanceStatus = provenanceStatus(v.BaseEventsAvailable, v.Evidence)
	v.BaseProvenance = v.BaseProvenanceStatus == "verified"
	if base && !v.BaseProvenance {
		return v, errors.New("probe_report_base_mismatch")
	}
	if base {
		phase("validate_rules", "start")
		err = verifyRevisionRules(ctx, p, id, v.RevisionID, v.Rules)
		phase("validate_rules", "returned")
		if err != nil {
			return v, err
		}
		v.ExactRuleMetadata = true
	}
	phase("validate_report", "complete")
	return v, nil
}
func provenanceStatus(available int64, total int) string {
	if available == 0 {
		return "unavailable"
	}
	if available == int64(total) {
		return "verified"
	}
	return "partial"
}

func revise(ctx context.Context, worker, api *pgxpool.Pool, id string, r *result) error {
	initial, err := validateReport(ctx, worker, id, false)
	r.Reports = append(r.Reports, initial)
	if err != nil {
		return err
	}
	for i := 1; i <= 2; i++ {
		if err = guard(ctx, api); err != nil {
			return err
		}
		version, currentBody, e := currentRevisionMetadata(ctx, api, id)
		if e != nil {
			return errors.New("probe_report_read_failed")
		}
		body := fmt.Sprintf("%s\nCapacity fixture note %d.\n", currentBody, i)
		callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		started := time.Now()
		phase("revise", "start")
		_, e = reporting.ChangeRevision(callCtx, api, id, version, reporting.RevisionChanges{Body: &body})
		phase("revise", "returned")
		cancel()
		o := operation{Name: "revise", Seconds: time.Since(started).Seconds()}
		if e != nil {
			o.Error = "probe_report_revision_failed"
		}
		r.Operations = append(r.Operations, o)
		if e != nil {
			return errors.New("probe_report_revision_failed")
		}
		v, e := validateReport(ctx, worker, id, false)
		r.Reports = append(r.Reports, v)
		if e != nil {
			return e
		}
		if v.EvidenceSHA256 != initial.EvidenceSHA256 || v.Version != initial.Version+int64(i) {
			return errors.New("probe_revision_evidence_changed")
		}
	}
	r.Stopped = "two_revisions_created"
	return nil
}
func cleanupPasses(ctx context.Context, limit int, pass func(context.Context) (retention.Progress, error)) ([]operation, error) {
	ops := []operation{}
	for i := 0; i < limit; i++ {
		if err := ctx.Err(); err != nil {
			return ops, err
		}
		callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		started := time.Now()
		phase("cleanup", "start")
		p, err := pass(callCtx)
		phase("cleanup", "returned")
		cancel()
		ops = append(ops, operation{Name: "cleanup", Seconds: time.Since(started).Seconds(), Deleted: p.Deleted, ProtectedEvents: p.ProtectedEvents, Error: safeError(err)})
		if err != nil {
			return ops, err
		}
		if p.Deleted == 0 {
			return ops, nil
		}
	}
	return ops, nil
}
