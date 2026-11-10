//go:build integration

package detection

import (
	"cheesetrap/internal/store/db"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cheesetrap/internal/domain"
	"cheesetrap/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

type contextQueryCounter struct {
	calls atomic.Int64
	gaps  atomic.Int64
}

func (c *contextQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "-- name: ListDetectionContext :many") {
		c.calls.Add(1)
	}
	if strings.Contains(data.SQL, "-- name: DetectionSensorGapIncidents :many") {
		c.gaps.Add(1)
	}
	return ctx
}
func (*contextQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestDetectionCursor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pools := map[string]*pgxpool.Pool{}
	for _, role := range []string{"MIGRATION", "COLLECTOR", "WORKER"} {
		raw := os.Getenv("CHEESETRAP_TEST_DETECTION_" + role + "_URL")
		if raw == "" {
			t.Fatal("isolated detection runner credentials required")
		}
		p, err := store.NewPool(ctx, raw)
		if err != nil {
			t.Fatal("detection database unavailable")
		}
		defer p.Close()
		pools[role] = p
	}
	owner, collector, worker := pools["MIGRATION"], pools["COLLECTOR"], pools["WORKER"]
	counter := &contextQueryCounter{}
	tracedConfig := worker.Config()
	tracedConfig.ConnConfig.Tracer = counter
	worker, err := pgxpool.NewWithConfig(ctx, tracedConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	exec := func(pool *pgxpool.Pool, sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal("fixture SQL failed")
		}
	}
	queryInt := func(sql string) int64 {
		t.Helper()
		var v int64
		if err := owner.QueryRow(ctx, sql).Scan(&v); err != nil {
			t.Fatal("database observation failed")
		}
		return v
	}
	const sensor = "10000000-0000-4000-8000-000000000201"
	const generation = "20000000-0000-4000-8000-000000000201"
	exec(collector, "INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES($1,'detection-fixture','cowrie')", sensor)
	exec(collector, "INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES($1,$2,'/fixture/events.jsonl',1,1)", generation, sensor)
	// This fixture allocator obeys the collector's shared cursor lock and creates
	// real committed events. The detection database is separate from ingestion tests.
	appendEvents := func(events []domain.Event) {
		t.Helper()
		tx, err := collector.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var seq int64
		if err = tx.QueryRow(ctx, "SELECT ingested_seq FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE").Scan(&seq); err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			seq++
			attrs, _ := json.Marshal(e.Attributes)
			if e.QualityFlags == nil {
				e.QualityFlags = []string{}
			}
			_, err = tx.Exec(ctx, `INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,ingested_at,source_ip,service,event_type,attributes,raw_hash,quality_flags,is_test,destination_ip,destination_port) VALUES($1,$2,$3,$3,1,$4,$5,$6,$7,$8,$9,$10,repeat('a',64),$11,$12,$13,$14)`, sensor, generation, seq, e.Engine, e.ObservedAt, e.IngestedAt, e.SourceIP, e.Service, e.EventType, attrs, e.QualityFlags, e.IsTest, e.DestinationIP, e.DestinationPort)
			if err != nil {
				t.Fatal("fixture insert failed")
			}
		}
		if _, err = tx.Exec(ctx, "UPDATE cheesetrap.processing_cursors SET ingested_seq=$1 WHERE singleton", seq); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	process := func(limit int) {
		t.Helper()
		if _, err := ProcessBatch(ctx, worker, limit); err != nil {
			t.Fatalf("processing failed: %v", err)
		}
	}
	events := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 9, Start: 60, Step: 60}, {Count: 1, Kind: "normal", Start: 300}}})
	appendEvents(events)
	process(5)
	if calls := counter.calls.Load(); calls != 0 {
		t.Fatalf("unbounded context query must not run, got %d", calls)
	}
	if queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors") != 5 {
		t.Fatal("continuous cursor did not complete the first five nonmatches")
	}
	if queryInt("SELECT count(*) FROM cheesetrap.detection_completions") != 5 || queryInt("SELECT count(*) FROM cheesetrap.detection_results") != 0 {
		t.Fatal("nonmatch completion or isolation from higher unprocessed sequences failed")
	}
	process(100)
	if queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors") != 10 || queryInt("SELECT count(*) FROM cheesetrap.detection_completions") != 10 {
		t.Fatal("normal interleaved event was not completed")
	}
	t.Run("context_excludes_unrelated_event_types", func(t *testing.T) {
		rows, err := db.New(worker).ListDetectionContext(ctx, db.ListDetectionContextParams{EventType: "cowrie.login.failed", SourceIp: netip.MustParseAddr(events[0].SourceIP), ProcessingSeq: 11, WindowStart: timestamp(events[0].ObservedAt.Add(-Window)), WindowEnd: timestamp(events[0].ObservedAt.Add(Window))})
		if err != nil || len(rows) != 9 {
			t.Fatalf("expected only nine completed login failures, got %d: %v", len(rows), err)
		}
	})
	t.Run("late_arrival_and_atomic_failure", func(t *testing.T) {
		appendEvents(fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 1}}}))
		// Fail the completion insert after the result and evidence inserts. All three
		// writes and the cursor must roll back, including any earlier work in a batch.
		exec(owner, `CREATE FUNCTION cheesetrap.test_detection_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected completion failure'; END $$; CREATE TRIGGER test_detection_failure BEFORE INSERT ON cheesetrap.detection_completions FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_detection_failure()`)
		defer owner.Exec(context.Background(), "DROP TRIGGER IF EXISTS test_detection_failure ON cheesetrap.detection_completions; DROP FUNCTION IF EXISTS cheesetrap.test_detection_failure()")
		if _, err := ProcessBatch(ctx, worker, 100); err == nil {
			t.Fatal("injected database failure was ignored")
		}
		if queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors") != 10 || queryInt("SELECT count(*) FROM cheesetrap.detection_results") != 0 || queryInt("SELECT count(*) FROM cheesetrap.evidence_chunk_members") != 0 || queryInt("SELECT count(*) FROM cheesetrap.evidence_chunks") != 0 || queryInt("SELECT count(*) FROM cheesetrap.detection_evidence_chunks") != 0 || queryInt("SELECT count(*) FROM cheesetrap.detection_completions") != 10 {
			t.Fatal("failure left partial detection state")
		}
		exec(owner, "DROP TRIGGER test_detection_failure ON cheesetrap.detection_completions")
		exec(owner, `CREATE SEQUENCE cheesetrap.test_evidence_insert_calls;
   CREATE FUNCTION cheesetrap.test_evidence_insert_count() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$
   BEGIN PERFORM nextval('cheesetrap.test_evidence_insert_calls'); RETURN NULL; END $$;
   CREATE TRIGGER test_evidence_insert_count AFTER INSERT ON cheesetrap.evidence_chunk_members FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.test_evidence_insert_count()`)
		defer owner.Exec(context.Background(), `DROP TRIGGER test_evidence_insert_count ON cheesetrap.evidence_chunk_members; DROP FUNCTION cheesetrap.test_evidence_insert_count(); DROP SEQUENCE cheesetrap.test_evidence_insert_calls`)
		process(100)
		if queryInt("SELECT count(*) FROM cheesetrap.detection_results WHERE evidence_representation='chunks-v1'") != 1 {
			t.Fatal("new processor result did not use chunk storage")
		}
		if calls := queryInt("SELECT last_value FROM cheesetrap.test_evidence_insert_calls"); calls != 1 {
			t.Fatalf("evidence must use one INSERT per result, got %d", calls)
		}
		if queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors") != 11 || queryInt("SELECT count(*) FROM cheesetrap.detection_results") != 1 || queryInt("SELECT count(*) FROM cheesetrap.evidence_chunk_members") != 10 {
			t.Fatal("late event retry lost result/evidence/cursor")
		}
		var seq int64
		var start, end time.Time
		var explain []byte
		if err := owner.QueryRow(ctx, "SELECT processing_ingestion_seq,window_start,window_end,explanation FROM cheesetrap.detection_results").Scan(&seq, &start, &end, &explain); err != nil {
			t.Fatal(err)
		}
		var explanation Explanation
		if json.Unmarshal(explain, &explanation) != nil || seq != 11 || !end.Equal(*events[8].ObservedAt) || end.Sub(start) != Window || explanation.Count != 10 {
			t.Fatal("late result was not attributed to its current ingestion trigger")
		}
	})
	if t.Failed() {
		return
	}
	t.Run("replay_is_idempotent_and_immutable", func(t *testing.T) {
		var before string
		if err := owner.QueryRow(ctx, "SELECT row_to_json(r)::text FROM cheesetrap.detection_results r").Scan(&before); err != nil {
			t.Fatal(err)
		}
		exec(owner, "UPDATE cheesetrap.processing_cursors SET detected_seq=10 WHERE singleton")
		process(100)
		process(100)
		var after string
		if err := owner.QueryRow(ctx, "SELECT row_to_json(r)::text FROM cheesetrap.detection_results r").Scan(&after); err != nil {
			t.Fatal(err)
		}
		if before != after || queryInt("SELECT count(*) FROM cheesetrap.detection_results") != 1 || queryInt("SELECT count(*) FROM cheesetrap.evidence_chunk_members") != 10 || queryInt("SELECT count(*) FROM cheesetrap.detection_completions") != 11 {
			t.Fatal("replay duplicated or mutated committed proof")
		}
	})
	t.Run("failure_mid_batch_does_not_skip_normal_events", func(t *testing.T) {
		appendEvents(fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 1, Kind: "normal", Start: 400}, {Count: 1, Start: 400}}}))
		exec(owner, `CREATE FUNCTION cheesetrap.test_mid_batch_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.ingestion_seq=13 THEN RAISE EXCEPTION 'injected middle failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_mid_batch_failure BEFORE INSERT ON cheesetrap.detection_completions FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_mid_batch_failure()`)
		defer owner.Exec(context.Background(), "DROP TRIGGER IF EXISTS test_mid_batch_failure ON cheesetrap.detection_completions; DROP FUNCTION IF EXISTS cheesetrap.test_mid_batch_failure()")
		if _, err := ProcessBatch(ctx, worker, 100); err == nil {
			t.Fatal("middle failure ignored")
		}
		if queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors") != 11 || queryInt("SELECT count(*) FROM cheesetrap.detection_completions") != 11 || queryInt("SELECT count(*) FROM cheesetrap.detection_results") != 1 || queryInt("SELECT count(*) FROM cheesetrap.evidence_chunk_members") != 10 {
			t.Fatal("middle failure advanced or leaked state")
		}
		exec(owner, "DROP TRIGGER test_mid_batch_failure ON cheesetrap.detection_completions")
		process(100)
		if queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors") != 13 || queryInt("SELECT count(*) FROM cheesetrap.detection_completions") != 13 {
			t.Fatal("retry skipped nonmatching sequence")
		}
	})
	t.Run("incident_holds_covered_events_without_mutating_past", func(t *testing.T) {
		exec(collector, `INSERT INTO cheesetrap.collection_gap_incidents(sensor_id,started_at,observed_through,causes) VALUES($1,'2026-10-19 13:00+00','2026-10-19 13:00+00',$2)`, sensor, []string{string(domain.GapSourceChange)})
		appendEvents(fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 1, Start: 420}}}))
		process(100)
		var eligible bool
		var explanation []byte
		if err := owner.QueryRow(ctx, "SELECT evidence_eligible,explanation FROM cheesetrap.detection_results WHERE processing_ingestion_seq=14").Scan(&eligible, &explanation); err != nil {
			t.Fatal(err)
		}
		if eligible || !strings.Contains(string(explanation), "collection_gap") {
			t.Fatal("persistent sensor gap did not hold evidence")
		}
		if queryInt("SELECT count(*) FROM cheesetrap.detection_results WHERE processing_ingestion_seq=11 AND evidence_eligible") != 1 {
			t.Fatal("historical result mutated after later gap")
		}
	})

	t.Run("takes_collector_cursor_lock_first", func(t *testing.T) {
		tx, err := collector.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, "SELECT ingested_seq FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE"); err != nil {
			t.Fatal(err)
		}
		blocked, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		if _, err := ProcessBatch(blocked, worker, 100); err == nil {
			t.Fatal("processor did not honor the collector cursor lock")
		}
		if queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors") != 14 {
			t.Fatal("blocked processor changed cursor")
		}
	})
	t.Run("concurrent_processors_serialize", func(t *testing.T) {
		appendEvents(fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 6, Kind: "normal", Start: 500}}}))
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for range 2 {
			wg.Add(1)
			go func() { defer wg.Done(); _, err := ProcessBatch(ctx, worker, 3); errs <- err }()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors") != 20 || queryInt("SELECT count(*) FROM cheesetrap.detection_completions") != 20 {
			t.Fatal("concurrent processors skipped or repeated completion")
		}
	})

	t.Run("budget_yields_atomic_prefix_to_waiting_collector", func(t *testing.T) {
		appendEvents(fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 6, Kind: "normal", Start: 600}}}))
		exec(owner, `CREATE SEQUENCE cheesetrap.test_detection_budget_calls;
   CREATE FUNCTION cheesetrap.test_detection_budget_delay() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$
   BEGIN PERFORM nextval('cheesetrap.test_detection_budget_calls'); PERFORM pg_advisory_xact_lock(1667781748,404); PERFORM pg_sleep(0.15); RETURN NEW; END $$;
   CREATE TRIGGER test_detection_budget_delay BEFORE INSERT ON cheesetrap.detection_completions FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_detection_budget_delay()`)
		defer owner.Exec(context.Background(), `DROP TRIGGER test_detection_budget_delay ON cheesetrap.detection_completions; DROP FUNCTION cheesetrap.test_detection_budget_delay(); DROP SEQUENCE cheesetrap.test_detection_budget_calls`)
		gate, err := owner.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer gate.Release()
		if _, err = gate.Exec(ctx, "SELECT pg_advisory_lock(1667781748,404)"); err != nil {
			t.Fatal(err)
		}
		defer gate.Exec(context.Background(), "SELECT pg_advisory_unlock(1667781748,404)")
		type outcome struct {
			progress Progress
			err      error
		}
		finished := make(chan outcome, 1)
		go func() {
			p, e := ProcessBatchWithBudget(ctx, worker, 1000, 20*time.Millisecond)
			finished <- outcome{p, e}
		}()
		deadline := time.Now().Add(5 * time.Second)
		for {
			var started bool
			if err := owner.QueryRow(ctx, "SELECT is_called FROM cheesetrap.test_detection_budget_calls").Scan(&started); err != nil {
				t.Fatal(err)
			}
			if started {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("slow completion did not start")
			}
			time.Sleep(time.Millisecond)
		}
		// The completion trigger has started, but no part of its transaction is visible.
		if queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors") != 20 || queryInt("SELECT count(*) FROM cheesetrap.detection_completions") != 20 {
			t.Fatal("uncommitted prefix visible")
		}
		// Release the trigger gate only after checking atomic invisibility.
		if _, err = gate.Exec(ctx, "SELECT pg_advisory_unlock(1667781748,404)"); err != nil {
			t.Fatal(err)
		}
		lockCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		tx, err := collector.Begin(lockCtx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		var cursor int64
		if err = tx.QueryRow(lockCtx, "SELECT detected_seq FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE").Scan(&cursor); err != nil {
			t.Fatal(err)
		}
		first := <-finished
		if first.err != nil || first.progress.Processed != 1 || !first.progress.HasMore || cursor != 21 {
			t.Fatalf("did not yield completed prefix: %+v, cursor=%d", first, cursor)
		}
		count := queryInt("SELECT count(*) FROM cheesetrap.detection_completions")
		if count != cursor {
			t.Fatalf("cursor/completion prefix not atomic: %d %d", cursor, count)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		// Subsequent jobs drain every remaining event without a gap or duplicate.
		for expected := int64(22); expected <= 26; expected++ {
			progress, err := ProcessBatchWithBudget(ctx, worker, 1000, 20*time.Millisecond)
			if err != nil || progress.Processed != 1 || progress.DetectedSeq != uint64(expected) || progress.HasMore != (expected < 26) {
				t.Fatalf("drain failed: %+v %v", progress, err)
			}
		}
		if queryInt("SELECT count(*) FROM cheesetrap.detection_completions") != 26 {
			t.Fatal("completion count differs from cursor")
		}
	})
	t.Run("cached_and_uncached_full_state_agree", func(t *testing.T) {
		snapshot := func() string {
			t.Helper()
			var state string
			err := owner.QueryRow(ctx, `SELECT jsonb_build_object(
    'results',(SELECT jsonb_agg(proof ORDER BY proof::text) FROM (
      SELECT (to_jsonb(r)-'detection_id'-'created_at'-'review_seq') || jsonb_build_object('evidence_ids',(SELECT jsonb_agg(e.event_id ORDER BY e.event_id) FROM cheesetrap.detection_evidence_chunks x JOIN cheesetrap.evidence_chunk_members e USING(chunk_id) WHERE x.detection_id=r.detection_id)) AS proof FROM cheesetrap.detection_results r) r),
    'completions',(SELECT jsonb_agg(to_jsonb(c)-'completed_at' ORDER BY ingestion_seq) FROM cheesetrap.detection_completions c),
    'cursor',(SELECT detected_seq FROM cheesetrap.processing_cursors))::text`).Scan(&state)
			if err != nil {
				t.Fatal(err)
			}
			return state
		}
		var before string
		for _, limits := range []contextCacheLimits{{}, {keys: 1, rows: 1, span: Window}} {
			exec(owner, `TRUNCATE cheesetrap.detection_evidence,cheesetrap.detection_evidence_chunks,cheesetrap.evidence_chunk_members,cheesetrap.evidence_chunks,cheesetrap.detection_results,cheesetrap.detection_completions; UPDATE cheesetrap.processing_cursors SET detected_seq=0`)
			if _, err := processBatchWithContextLimits(ctx, worker, 1000, 0, limits); err != nil {
				t.Fatal(err)
			}
			// A gap was inserted after sequence 13 in the original run. Remove that
			// retrospective difference from this comparison by comparing two replays.
			if limits.keys == 0 {
				before = snapshot()
			} else if after := snapshot(); after != before {
				t.Fatal("cache fallback changed complete results, evidence, completions, or cursor")
			}
		}
		exec(owner, `TRUNCATE cheesetrap.detection_evidence,cheesetrap.detection_evidence_chunks,cheesetrap.evidence_chunk_members,cheesetrap.evidence_chunks,cheesetrap.detection_results,cheesetrap.detection_completions; UPDATE cheesetrap.processing_cursors SET detected_seq=0`)
		process(1000)
		if after := snapshot(); after != before {
			t.Fatal("cache changed complete results, evidence, completions, or cursor")
		}
	})
	t.Run("missing_sequence_fails_closed", func(t *testing.T) {
		exec(collector, "UPDATE cheesetrap.processing_cursors SET ingested_seq=27 WHERE singleton")
		if _, err := ProcessBatch(ctx, worker, 100); err == nil {
			t.Fatal("cursor accepted a missing committed sequence")
		}
		if queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors") != 26 {
			t.Fatal("cursor skipped missing sequence")
		}
	})
	t.Run("invalid_batch_limit", func(t *testing.T) {
		for _, n := range []int{0, -1, 1001} {
			if _, err := ProcessBatch(ctx, worker, n); err == nil {
				t.Fatal("invalid batch limit accepted")
			}
		}
	})
	t.Run("all_rules_exact_legacy_snapshot_and_mixed_replay", func(t *testing.T) {
		// Repair the deliberately missing sequence from the preceding test.
		exec(owner, "UPDATE cheesetrap.processing_cursors SET ingested_seq=26 WHERE singleton")
		mixed := fixtureEvents(ruleFixture{Groups: []fixtureGroup{
			{Count: 80, Start: 1800, Step: 5},
			{Count: 24, Kind: "web", Start: 1800, Step: 5, Paths: SuspiciousPaths()},
			{Count: 12, IP: "198.51.100.21", Start: 1800, Step: 5},
			{Count: 24, Kind: "web", Start: 1800, Step: 5, Paths: []string{"/../etc/passwd"}},
			{Count: 1, Kind: "normal", Start: 1850},
			{Count: 1, Start: 1810}, // Late observed time and partial window.
			{Count: 1, Kind: "web", Start: 1810, Paths: []string{"/.env"}},
		}})
		for i := range mixed {
			if mixed[i].Service == "http" && i%2 == 0 {
				mixed[i].Service = "https"
			}
		}
		appendEvents(mixed)
		exec(owner, `INSERT INTO cheesetrap.rule_config_versions(settings_version,effective_from_seq,config) VALUES(2,40,'{"ssh_repeat_threshold":12,"web_repeat_threshold":22,"web_distinct_path_threshold":4}')`)
		process(1000)
		// Snapshot every semantic result field and the exact membership, omitting
		// only storage metadata and generated identities/timestamps.
		snapshot := func() string {
			t.Helper()
			var value string
			err := owner.QueryRow(ctx, `SELECT jsonb_agg(proof ORDER BY proof::text)::text FROM (
 SELECT (to_jsonb(r)-'detection_id'-'created_at'-'review_seq'-'evidence_representation'-'evidence_state'-'evidence_hash'-'evidence_hash_scheme') || jsonb_build_object('evidence_ids',
 (SELECT jsonb_agg(event_id ORDER BY event_id) FROM (
 SELECT event_id FROM cheesetrap.detection_evidence WHERE detection_id=r.detection_id
 UNION ALL SELECT m.event_id FROM cheesetrap.detection_evidence_chunks c JOIN cheesetrap.evidence_chunk_members m USING(chunk_id) WHERE c.detection_id=r.detection_id) membership)) AS proof
 FROM cheesetrap.detection_results r) proofs`).Scan(&value)
			if err != nil {
				t.Fatal(err)
			}
			return value
		}
		chunkSnapshot := snapshot()
		if queryInt("SELECT count(DISTINCT bucket_no) FROM cheesetrap.evidence_chunks") < 2 {
			t.Fatal("fixture must cross a fixed sequence bucket boundary")
		}
		rows, err := db.New(worker).ListDetectionBatch(ctx, db.ListDetectionBatchParams{AfterSeq: 0, ThroughSeq: 1000, BatchLimit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		var expected []Result
		var history []domain.Event
		for _, row := range rows {
			e, err := domainEvent(row)
			if err != nil {
				t.Fatal(err)
			}
			e.QualityFlags = append(e.QualityFlags, "collection_gap")
			v, err := db.New(worker).RuleConfigAt(ctx, row.IngestionSeq)
			if err != nil {
				t.Fatal(err)
			}
			var config Config
			if err := json.Unmarshal(v.Config, &config); err != nil {
				t.Fatal(err)
			}
			results, err := EvaluateConfigured(e, history, config, v.SettingsVersion)
			if err != nil {
				t.Fatal(err)
			}
			expected = append(expected, results...)
			history = append(history, e)
		}
		if queryInt("SELECT count(DISTINCT rule_id) FROM cheesetrap.detection_results") != 3 {
			t.Fatal("fixture must exercise all three rules")
		}
		exec(owner, `TRUNCATE cheesetrap.detection_evidence,cheesetrap.detection_evidence_chunks,cheesetrap.evidence_chunk_members,cheesetrap.evidence_chunks,cheesetrap.detection_results`)
		tx, err := worker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		q := db.New(tx)
		if _, err := q.LockProcessingCursors(ctx); err != nil {
			t.Fatal(err)
		}
		for _, result := range expected {
			if err := saveLegacyResultForTest(ctx, q, result); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if snapshot() != chunkSnapshot {
			t.Fatal("complete chunk result snapshot differs from legacy uncached evaluator snapshot")
		}
		// Reprocess historical legacy roots; new events must coexist as chunks.
		exec(owner, "UPDATE cheesetrap.processing_cursors SET detected_seq=0 WHERE singleton")
		process(1000)
		if snapshot() != chunkSnapshot || queryInt("SELECT count(*) FROM cheesetrap.evidence_chunks") != 0 {
			t.Fatal("legacy retry changed proof or converted representation")
		}
		appendEvents(fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 2, Start: 1815}}}))
		cursorBefore := queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors")
		prefix, err := ProcessBatchWithBudget(ctx, worker, 1000, time.Nanosecond)
		if err != nil || prefix.Processed != 1 || !prefix.HasMore || prefix.DetectedSeq != uint64(cursorBefore+1) {
			t.Fatalf("matching budget prefix failed: %+v %v", prefix, err)
		}
		if queryInt("SELECT count(*) FROM cheesetrap.detection_results WHERE evidence_representation='chunks-v1'") == 0 || queryInt("SELECT count(*) FROM cheesetrap.detection_evidence_chunks") == 0 || queryInt("SELECT count(*) FROM cheesetrap.evidence_chunk_members") == 0 || queryInt("SELECT max(ingestion_seq) FROM cheesetrap.detection_completions") != cursorBefore+1 {
			t.Fatal("matching prefix omitted storage or completion")
		}
		process(1000)
		if queryInt("SELECT count(*) FROM cheesetrap.detection_results WHERE evidence_representation='chunks-v1'") == 0 || queryInt("SELECT count(*) FROM cheesetrap.detection_results WHERE evidence_representation='legacy'") == 0 {
			t.Fatal("mixed representation fixture missing")
		}
		// Owner-only fixture simulates retirement. Runtime retry must fail closed
		// without committing any of the preceding completed prefix.
		exec(owner, `ALTER TABLE cheesetrap.detection_results DISABLE TRIGGER guard_evidence_root; UPDATE cheesetrap.detection_results SET evidence_state='retiring' WHERE processing_ingestion_seq=11; ALTER TABLE cheesetrap.detection_results ENABLE TRIGGER guard_evidence_root; UPDATE cheesetrap.processing_cursors SET detected_seq=0 WHERE singleton`)
		before := snapshot()
		if _, err := ProcessBatch(ctx, worker, 1000); !errors.Is(err, ErrProcessing) || !errors.Is(err, ErrRetiredResult) {
			t.Fatalf("retiring legacy retry must expose explicit outcome: %v", err)
		}
		if snapshot() != before || queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors") != 0 {
			t.Fatal("retiring retry committed a partial prefix")
		}
		exec(owner, `ALTER TABLE cheesetrap.detection_results DISABLE TRIGGER guard_evidence_root; UPDATE cheesetrap.detection_results SET evidence_state='active' WHERE evidence_state='retiring'; UPDATE cheesetrap.detection_results SET evidence_state='retiring' WHERE processing_ingestion_seq=(SELECT max(processing_ingestion_seq) FROM cheesetrap.detection_results); ALTER TABLE cheesetrap.detection_results ENABLE TRIGGER guard_evidence_root; UPDATE cheesetrap.processing_cursors SET detected_seq=ingested_seq-1 WHERE singleton`)
		cursorBefore = queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors")
		before = snapshot()
		if _, err := ProcessBatch(ctx, worker, 1000); !errors.Is(err, ErrProcessing) || !errors.Is(err, ErrRetiredResult) {
			t.Fatalf("retiring chunk retry must expose explicit outcome: %v", err)
		}
		if snapshot() != before || queryInt("SELECT detected_seq FROM cheesetrap.processing_cursors") != cursorBefore {
			t.Fatal("retiring chunk retry changed committed proof")
		}
	})

	t.Run("old_incident_does_not_flag_later_events", func(t *testing.T) {
		exec(owner, `ALTER TABLE cheesetrap.detection_results DISABLE TRIGGER guard_evidence_root; UPDATE cheesetrap.detection_results SET evidence_state='active' WHERE evidence_state='retiring'; ALTER TABLE cheesetrap.detection_results ENABLE TRIGGER guard_evidence_root`)
		process(1000)
		late := fixtureEvents(ruleFixture{Groups: []fixtureGroup{{Count: 12, Start: 2400, Step: 1, IP: "198.51.100.99"}}})
		at := time.Date(2026, 10, 19, 14, 0, 0, 0, time.UTC)
		for i := range late {
			late[i].IngestedAt = &at
		}
		appendEvents(late)
		counter.gaps.Store(0)
		process(1000)
		if calls := counter.gaps.Load(); calls != 1 {
			t.Fatalf("gap lookups=%d for one sensor batch", calls)
		}
		var reasons bool
		if err := owner.QueryRow(ctx, `SELECT bool_or(explanation::text LIKE '%collection_gap%') FROM cheesetrap.detection_results WHERE source_ip='198.51.100.99'`).Scan(&reasons); err != nil {
			t.Fatal(err)
		}
		if reasons {
			t.Fatal("old incident flagged later events")
		}
	})

}

// The historical writer is retained only as an independent compatibility oracle.
func saveLegacyResultForTest(ctx context.Context, q *db.Queries, r Result) error {
	explanation, err := json.Marshal(r.Explanation)
	if err != nil {
		return err
	}
	var trigger pgtype.UUID
	if err := trigger.Scan(r.ProcessingEventID); err != nil {
		return err
	}
	id, err := q.InsertDetectionResult(ctx, db.InsertDetectionResultParams{RuleID: r.RuleID, RuleVersion: r.RuleVersion, SignatureID: r.SignatureID, SignatureVersion: r.SignatureVersion, ProcessingEventID: trigger, ProcessingIngestionSeq: int64(r.ProcessingIngestionSeq), SourceIp: netip.MustParseAddr(r.SourceIP), WindowStart: timestamp(r.Explanation.WindowStart), WindowEnd: timestamp(r.Explanation.WindowEnd), EvidenceHash: r.EvidenceHash, EvidenceCount: int32(len(r.EvidenceIDs)), EvidenceEligible: r.EvidenceEligible, AutoApprovalAllowed: r.AutoApprovalAllowed, Explanation: explanation, SettingsVersion: r.SettingsVersion})
	if err != nil {
		return err
	}
	ids := make([]pgtype.UUID, len(r.EvidenceIDs))
	for i, v := range r.EvidenceIDs {
		if err := ids[i].Scan(v); err != nil {
			return err
		}
	}
	return q.InsertDetectionEvidence(ctx, db.InsertDetectionEvidenceParams{DetectionID: id, EventIds: ids})
}
