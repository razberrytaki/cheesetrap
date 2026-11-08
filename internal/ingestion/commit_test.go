//go:build integration

package ingestion

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"cheesetrap/internal/store"
	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The initial RED used a test-only stub here so it reached real PostgreSQL.
// This adapter now calls the production transaction with trusted source settings.
func commitTest(ctx context.Context, pool *pgxpool.Pool, sensor string, batch TailerBatch) error {
	source := testSource()
	source.SensorID = sensor
	source.Name = sensor
	return CommitBatch(ctx, pool, source, batch)
}

func TestCommitBatch(t *testing.T) {
	if os.Getenv("CHEESETRAP_COMMIT_CHILD") != "" {
		commitChild(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_COLLECTOR_URL"))
	if err != nil {
		t.Fatal("isolated collector database required")
	}
	defer pool.Close()
	sensor := "10000000-0000-4000-8000-000000000104"
	batch := commitFixture(t, "20000000-0000-4000-8000-000000000104", 2)
	t.Run("identical_replay_and_distinct_offsets", func(t *testing.T) {
		if err := commitTest(ctx, pool, sensor, batch); err != nil {
			t.Fatalf("atomic batch commit failed: %v", err)
		}
		if err := commitTest(ctx, pool, sensor, batch); err != nil {
			t.Fatal("replay failed")
		}
		var count int
		var first, last, cursor, offset int64
		if err := pool.QueryRow(ctx, "SELECT count(*), min(ingestion_seq), max(ingestion_seq) FROM cheesetrap.events WHERE sensor_id=$1", sensor).Scan(&count, &first, &last); err != nil {
			t.Fatal("event observation failed")
		}
		if err := pool.QueryRow(ctx, "SELECT ingested_seq FROM cheesetrap.processing_cursors").Scan(&cursor); err != nil {
			t.Fatal("cursor observation failed")
		}
		if err := pool.QueryRow(ctx, "SELECT byte_offset FROM cheesetrap.checkpoints WHERE sensor_id=$1", sensor).Scan(&offset); err != nil {
			t.Fatal("checkpoint observation failed")
		}
		if count != 2 || last != first+1 || cursor != last || offset != batch.Records[1].EndOffset {
			t.Fatalf("atomic evidence mismatch: events=%d first=%d last=%d cursor=%d offset=%d", count, first, last, cursor, offset)
		}
	})
	t.Run("rejects_checkpoint_holes_and_rolls_back", func(t *testing.T) {
		b := commitFixture(t, "20000000-0000-4000-8000-000000000105", 2)
		b.Records = b.Records[1:]
		if commitTest(ctx, pool, "10000000-0000-4000-8000-000000000105", b) == nil {
			t.Fatal("skipped uncommitted prefix")
		}
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.file_generations WHERE file_generation_id=$1", b.Generations[0].ID).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed batch left generation metadata")
		}
	})
	t.Run("rejections_are_durable_and_consume_no_sequence", func(t *testing.T) {
		b := commitFixture(t, "20000000-0000-4000-8000-000000000106", 2)
		b.Records[0].raw = []byte(`{"password":"must-never-persist"}`)
		b.Records[1].raw = nil
		b.Records[1].Problem = "record_too_large"
		var before, after int64
		if err := pool.QueryRow(ctx, "SELECT ingested_seq FROM cheesetrap.processing_cursors").Scan(&before); err != nil {
			t.Fatal("read cursor failed")
		}
		sensor := "10000000-0000-4000-8000-000000000106"
		for range 2 {
			if commitTest(ctx, pool, sensor, b) != nil {
				t.Fatal("rejection commit failed")
			}
		}
		var count int
		var text string
		if err := pool.QueryRow(ctx, "SELECT count(*),string_agg(reason,' ') FROM cheesetrap.ingestion_rejections WHERE sensor_id=$1", sensor).Scan(&count, &text); err != nil || count != 2 || !strings.Contains(text, "adapter_rejected") || !strings.Contains(text, "record_too_large") {
			t.Fatal("bounded rejection metadata missing")
		}
		if err := pool.QueryRow(ctx, "SELECT ingested_seq FROM cheesetrap.processing_cursors").Scan(&after); err != nil || after != before {
			t.Fatal("rejections consumed sequence")
		}
	})
	t.Run("database_failure_rolls_back_witness_and_retries", func(t *testing.T) {
		migration, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_MIGRATION_URL"))
		if err != nil {
			t.Fatal("migration test connection failed")
		}
		defer migration.Close(ctx)
		sql := `CREATE FUNCTION cheesetrap.test_fail_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test failure'; END $$; CREATE TRIGGER test_fail_checkpoint BEFORE INSERT OR UPDATE ON cheesetrap.checkpoints FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_fail_checkpoint()`
		if _, err := migration.Exec(ctx, sql); err != nil {
			t.Fatal("failure trigger creation failed")
		}
		defer migration.Exec(context.Background(), "DROP TRIGGER IF EXISTS test_fail_checkpoint ON cheesetrap.checkpoints; DROP FUNCTION IF EXISTS cheesetrap.test_fail_checkpoint()")
		b := commitFixture(t, "20000000-0000-4000-8000-000000000107", 1)
		sensor := "10000000-0000-4000-8000-000000000107"
		if commitTest(ctx, pool, sensor, b) == nil {
			t.Fatal("database failure ignored")
		}
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.events WHERE sensor_id=$1", sensor).Scan(&count); err != nil || count != 0 {
			t.Fatal("event escaped failed transaction")
		}
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.file_generations WHERE sensor_id=$1", sensor).Scan(&count); err != nil || count != 0 {
			t.Fatal("witness escaped failed transaction")
		}
		if _, err := migration.Exec(ctx, "DROP TRIGGER test_fail_checkpoint ON cheesetrap.checkpoints"); err != nil {
			t.Fatal("failure trigger removal failed")
		}
		if commitTest(ctx, pool, sensor, b) != nil {
			t.Fatal("unchanged batch retry failed")
		}
	})
	t.Run("witness_restore_and_stale_retry", func(t *testing.T) {
		b := commitFixture(t, "20000000-0000-4000-8000-000000000108", 2)
		sensor := "10000000-0000-4000-8000-000000000108"
		stale := b
		stale.Records = append([]TailerRecord(nil), b.Records[:1]...)
		stale.Generations = append([]FileGeneration(nil), b.Generations...)
		stale.Status.Generations = append([]GenerationStatus(nil), b.Status.Generations...)
		if commitTest(ctx, pool, sensor, b) != nil {
			t.Fatal("initial witness commit failed")
		}
		stale.Generations[0].ObservedSize = stale.Records[0].EndOffset
		stale.Generations[0].FingerprintBytes = 0
		stale.Generations[0].FingerprintSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		stale.Status.Generations = nil
		if commitTest(ctx, pool, sensor, stale) != nil {
			t.Fatal("stale replay failed")
		}
		var size, offset int64
		var n int
		var hash string
		if err := pool.QueryRow(ctx, "SELECT observed_size,fingerprint_bytes,fingerprint_sha256,byte_offset FROM cheesetrap.file_generations JOIN cheesetrap.checkpoints USING(sensor_id,file_generation_id) WHERE sensor_id=$1", sensor).Scan(&size, &n, &hash, &offset); err != nil {
			t.Fatal("restore witness missing")
		}
		want := b.Generations[0]
		if size != want.ObservedSize || n != want.FingerprintBytes || hash != want.FingerprintSHA256 || offset != b.Records[1].EndOffset {
			t.Fatal("stale replay regressed checkpoint or witnesses")
		}
	})
	t.Run("emitted_and_live_generation_snapshots_survive_together", func(t *testing.T) {
		b := commitFixture(t, "20000000-0000-4000-8000-000000000113", 1)
		sensor := "10000000-0000-4000-8000-000000000113"
		old := b.Generations[0]
		fresh := old
		fresh.ID = "20000000-0000-4000-8000-000000000114"
		fresh.ObservedSize = 0
		fresh.FingerprintBytes = 0
		fresh.FingerprintSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		b.Status.Generations = []GenerationStatus{{Generation: fresh}}
		b.Status.CollectionGap = true
		b.Status.Diagnostics = []TailerDiagnostic{{Code: "file_truncated", GenerationID: old.ID, At: time.Now()}}
		if commitTest(ctx, pool, sensor, b) != nil {
			t.Fatal("snapshot commit failed")
		}
		var count int
		if pool.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.file_generations WHERE sensor_id=$1", sensor).Scan(&count) != nil || count != 2 {
			t.Fatal("emitted generation replaced by live snapshot")
		}
		var flags []string
		if pool.QueryRow(ctx, "SELECT quality_flags FROM cheesetrap.events WHERE sensor_id=$1", sensor).Scan(&flags) != nil || !slices.Contains(flags, "collection_gap") {
			t.Fatal("gap missing from event quality")
		}
		points, err := loadResume(ctx, db.New(pool), sensor, filepath.Dir(old.Path))
		if err != nil || len(points) != 1 || points[0].Generation.ID != fresh.ID || points[0].ByteOffset != 0 {
			t.Fatal("retired generation restored or live metadata lost")
		}
	})
	t.Run("identity_conflicts_and_legacy_boundaries_are_rejected", func(t *testing.T) {
		b := commitFixture(t, "20000000-0000-4000-8000-000000000115", 1)
		sensor := "10000000-0000-4000-8000-000000000115"
		if commitTest(ctx, pool, sensor, b) != nil {
			t.Fatal("fixture commit")
		}
		if commitTest(ctx, pool, "10000000-0000-4000-8000-000000000116", b) != ErrBatch {
			t.Fatal("generation stolen by another sensor")
		}
		owner, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_MIGRATION_URL"))
		if err != nil {
			t.Fatal("owner connection")
		}
		defer owner.Close(ctx)
		if _, err := owner.Exec(ctx, "UPDATE cheesetrap.events SET byte_end_offset=NULL WHERE sensor_id=$1", sensor); err != nil {
			t.Fatal("legacy boundary fixture")
		}
		if commitTest(ctx, pool, sensor, b) != ErrBatch {
			t.Fatal("legacy missing end boundary accepted as replay")
		}
		if _, err := owner.Exec(ctx, "UPDATE cheesetrap.file_generations SET observed_size=0,fingerprint_bytes=0,fingerprint_sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' WHERE sensor_id=$1", sensor); err != nil {
			t.Fatal("legacy witness fixture")
		}
		if _, err := loadResume(ctx, db.New(pool), sensor, filepath.Dir(b.Generations[0].Path)); err != ErrBatch {
			t.Fatal("nonempty checkpoint accepted with legacy empty witness")
		}
	})

	t.Run("generation_retirement_tolerates_host_clock_ahead", func(t *testing.T) {
		b := commitFixture(t, "20000000-0000-4000-8000-000000000117", 1)
		sensor := "10000000-0000-4000-8000-000000000117"
		b.Generations[0].CreatedAt = time.Now().Add(time.Hour)
		b.Status.Generations[0].Generation = b.Generations[0]
		b.Status.CollectionGap = true
		b.Status.Diagnostics = []TailerDiagnostic{{Code: "resume_unavailable", GenerationID: b.Generations[0].ID}}
		if commitTest(ctx, pool, sensor, b) != nil {
			t.Fatal("host clock skew prevented durable generation retirement")
		}
		var closed bool
		if pool.QueryRow(ctx, "SELECT closed_at IS NOT NULL AND closed_at>=created_at FROM cheesetrap.file_generations WHERE sensor_id=$1", sensor).Scan(&closed) != nil || !closed {
			t.Fatal("retirement time invariant failed")
		}
	})

	t.Run("initial_sensor_preserves_observation_lower_bound", func(t *testing.T) {
		for i, initialGap := range []bool{false, true} {
			t.Run(fmt.Sprintf("gap_%t", initialGap), func(t *testing.T) {
				sensor := fmt.Sprintf("10000000-0000-4000-8000-%012d", 118+i)
				generation := fmt.Sprintf("20000000-0000-4000-8000-%012d", 118+i)
				observed, err := db.New(pool).CommitClock(ctx)
				if err != nil {
					t.Fatal("initial observation clock failed")
				}
				b := commitFixture(t, generation, 1)
				b.ObservationStartedAt = observed.Time
				b.Status.CollectionGap = initialGap
				if commitTest(ctx, pool, sensor, b) != nil {
					t.Fatal("first sensor commit failed")
				}
				var bound time.Time
				if pool.QueryRow(ctx, "SELECT last_observation_at FROM cheesetrap.sensors WHERE sensor_id=$1", sensor).Scan(&bound) != nil || !bound.Equal(observed.Time) {
					t.Fatal("initial sensor discarded supplied pre-Poll observation lower bound")
				}
				if initialGap {
					var started time.Time
					if pool.QueryRow(ctx, "SELECT started_at FROM cheesetrap.ingestion_gaps WHERE sensor_id=$1", sensor).Scan(&started) != nil || !started.Equal(observed.Time) {
						t.Fatal("initial gap omitted pre-Poll observation interval")
					}
				}
				b.ObservationStartedAt = time.Time{}
				if commitTest(ctx, pool, sensor, b) != nil {
					t.Fatal("zero-observation replay failed")
				}
				if pool.QueryRow(ctx, "SELECT last_observation_at FROM cheesetrap.sensors WHERE sensor_id=$1", sensor).Scan(&bound) != nil || !bound.Equal(observed.Time) {
					t.Fatal("zero-observation replay advanced existing lower bound")
				}
			})
		}
	})

	t.Run("concurrent_batches_and_window_boundary", func(t *testing.T) { testConcurrentBoundary(t, ctx, pool) })
	t.Run("process_exit_before_and_after_commit", func(t *testing.T) { testCommitProcessExit(t, ctx, pool) })

}

func commitFixture(t *testing.T, id string, count int) TailerBatch {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cowrie.json")
	line := []byte(`{"eventid":"cowrie.session.connect","src_ip":"198.51.100.20","src_port":34567,"dst_ip":"192.0.2.2","dst_port":2222,"session":"abc"}` + "\n")
	var data []byte
	for range count {
		data = append(data, line...)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal("fixture write failed")
	}
	tail, err := NewTailer(TailerConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer tail.Close()
	batch, err := tail.Poll(context.Background())
	if err != nil || len(batch.Records) != count {
		t.Fatal("fixture poll failed")
	}
	batch.Generations[0].ID = id
	batch.Status.Generations[0].Generation.ID = id
	for i := range batch.Records {
		batch.Records[i].GenerationID = id
	}
	return batch
}

// Wait on an actual server lock state, never an elapsed delay as proof of order.
func waitDatabase(t *testing.T, ctx context.Context, c *pgx.Conn, query string, args ...any) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		_, _ = c.Exec(ctx, "SELECT pg_stat_clear_snapshot()")
		var yes bool
		if c.QueryRow(ctx, query, args...).Scan(&yes) == nil && yes {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("database synchronization timed out")
		case <-ticker.C:
		}
	}
}
func testConcurrentBoundary(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	observer, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_COLLECTOR_URL"))
	if err != nil {
		t.Fatal("observer connection failed")
	}
	defer observer.Close(ctx)
	gate, err := observer.Begin(ctx)
	if err != nil {
		t.Fatal("gate begin failed")
	}
	defer gate.Rollback(ctx)
	var before int64
	if gate.QueryRow(ctx, "SELECT ingested_seq FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE").Scan(&before) != nil {
		t.Fatal("cursor gate lock failed")
	}
	batches := []TailerBatch{commitFixture(t, "20000000-0000-4000-8000-000000000109", 2), commitFixture(t, "20000000-0000-4000-8000-000000000110", 2)}
	sensors := []string{"10000000-0000-4000-8000-000000000109", "10000000-0000-4000-8000-000000000110"}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := range batches {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results <- commitTest(ctx, pool, sensors[i], batches[i]) }(i)
	}
	waitDatabase(t, ctx, observer, "SELECT count(*)>=2 FROM pg_stat_activity WHERE usename=current_user AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%LockProcessingCursors%'")
	var boundary time.Time
	if gate.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&boundary) != nil {
		t.Fatal("database boundary observation failed")
	}
	if gate.Commit(ctx) != nil {
		t.Fatal("gate release failed")
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("concurrent batch failed")
		}
	}
	// A worker seals under exactly the same row lock and sees the full committed
	// prefix. An event blocked before the boundary belongs after that boundary.
	worker, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_WORKER_URL"))
	if err != nil {
		t.Fatal("worker observation connection failed")
	}
	defer worker.Close(ctx)
	seal, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal("worker begin failed")
	}
	defer seal.Rollback(ctx)
	var after int64
	if seal.QueryRow(ctx, "SELECT ingested_seq FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE").Scan(&after) != nil || after != before+4 {
		t.Fatal("commit order lost or sequence has holes")
	}
	var count, early int
	var first, last int64
	// The shared harness also has API pagination fixtures beyond this cursor.
	// Assert precisely the committed interval sealed above.
	if seal.QueryRow(ctx, "SELECT count(*),count(*) FILTER(WHERE ingested_at<$1),min(ingestion_seq),max(ingestion_seq) FROM cheesetrap.events WHERE ingestion_seq>$2 AND ingestion_seq<=$3", boundary, before, after).Scan(&count, &early, &first, &last) != nil || count != 4 || early != 0 || first != before+1 || last != after {
		t.Fatal("late commit crossed sealed window boundary or lost contiguous sequence")
	}
}

type childPayload struct {
	Sensor string
	Batch  TailerBatch
	Raw    [][]byte
}

func commitChild(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("CHEESETRAP_COMMIT_CHILD"))
	if err != nil {
		t.Fatal("child fixture read")
	}
	var payload childPayload
	if json.Unmarshal(data, &payload) != nil {
		t.Fatal("child fixture decode")
	}
	for i := range payload.Batch.Records {
		payload.Batch.Records[i].raw = payload.Raw[i]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_COLLECTOR_URL"))
	if err != nil {
		t.Fatal("child database connect")
	}
	defer pool.Close()
	if commitTest(ctx, pool, payload.Sensor, payload.Batch) != nil {
		t.Fatal("child commit failed")
	}
	_, _ = os.Stdout.WriteString("COMMITTED\n")
	for {
		time.Sleep(time.Hour)
	}
}
func testCommitProcessExit(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	migration, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_MIGRATION_URL"))
	if err != nil {
		t.Fatal("migration connection")
	}
	defer migration.Close(ctx)
	observer, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_COLLECTOR_URL"))
	if err != nil {
		t.Fatal("observer connection")
	}
	defer observer.Close(ctx)
	for _, stage := range []string{"before", "after"} {
		t.Run(stage, func(t *testing.T) {
			sensor, id := "10000000-0000-4000-8000-000000000111", "20000000-0000-4000-8000-000000000111"
			if stage == "after" {
				sensor, id = "10000000-0000-4000-8000-000000000112", "20000000-0000-4000-8000-000000000112"
			}
			batch := commitFixture(t, id, 2)
			payload := childPayload{Sensor: sensor, Batch: batch}
			for _, r := range batch.Records {
				payload.Raw = append(payload.Raw, r.Bytes())
			}
			data, _ := json.Marshal(payload)
			path := filepath.Join(t.TempDir(), "child.json")
			if os.WriteFile(path, data, 0600) != nil {
				t.Fatal("child fixture write")
			}
			var before int64
			if observer.QueryRow(ctx, "SELECT ingested_seq FROM cheesetrap.processing_cursors").Scan(&before) != nil {
				t.Fatal("initial cursor")
			}
			if stage == "before" {
				if _, err := observer.Exec(ctx, "SELECT pg_advisory_lock(1667781748,105)"); err != nil {
					t.Fatal("advisory gate")
				}
				if _, err := migration.Exec(ctx, `CREATE FUNCTION cheesetrap.test_checkpoint_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(1667781748,105); RETURN NEW; END $$; CREATE TRIGGER test_checkpoint_gate BEFORE INSERT OR UPDATE ON cheesetrap.checkpoints FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_checkpoint_gate()`); err != nil {
					t.Fatal("checkpoint gate creation")
				}
				defer migration.Exec(context.Background(), "DROP TRIGGER IF EXISTS test_checkpoint_gate ON cheesetrap.checkpoints; DROP FUNCTION IF EXISTS cheesetrap.test_checkpoint_gate()")
				defer observer.Exec(context.Background(), "SELECT pg_advisory_unlock(1667781748,105)")
			}
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCommitBatch$")
			command.Env = append(os.Environ(), "CHEESETRAP_COMMIT_CHILD="+path)
			pipe, err := command.StdoutPipe()
			if err != nil {
				t.Fatal("child stdout")
			}
			if command.Start() != nil {
				t.Fatal("child start")
			}
			defer command.Process.Kill()
			if stage == "before" {
				waitDatabase(t, ctx, observer, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=current_user AND wait_event='advisory' AND query LIKE '%SetCheckpoint%')")
				var count int
				if observer.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.events WHERE sensor_id=$1", sensor).Scan(&count) != nil || count != 0 {
					t.Fatal("uncommitted events visible")
				}
			} else {
				ready := make(chan bool, 1)
				go func() {
					scanner := bufio.NewScanner(pipe)
					for scanner.Scan() {
						if scanner.Text() == "COMMITTED" {
							ready <- true
							return
						}
					}
					ready <- false
				}()
				select {
				case ok := <-ready:
					if !ok {
						t.Fatal("child never committed")
					}
				case <-ctx.Done():
					t.Fatal("child commit timeout")
				}
			}
			if command.Process.Kill() != nil {
				t.Fatal("child kill")
			}
			_ = command.Wait()
			waitDatabase(t, ctx, observer, "SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=current_user AND wait_event='advisory' AND query LIKE '%SetCheckpoint%')")
			if stage == "before" {
				if _, err := migration.Exec(ctx, "DROP TRIGGER test_checkpoint_gate ON cheesetrap.checkpoints"); err != nil {
					t.Fatal("remove checkpoint gate")
				}
			}
			var count int
			var cursor int64
			if observer.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.file_generations WHERE sensor_id=$1", sensor).Scan(&count) != nil {
				t.Fatal("generation observation")
			}
			if stage == "before" && count != 0 || stage == "after" && count != 1 {
				t.Fatal("generation atomicity after process exit")
			}
			if observer.QueryRow(ctx, "SELECT ingested_seq FROM cheesetrap.processing_cursors").Scan(&cursor) != nil {
				t.Fatal("cursor observation")
			}
			if stage == "before" && cursor != before || stage == "after" && cursor != before+2 {
				t.Fatal("cursor atomicity after process exit")
			}
			if commitTest(ctx, pool, sensor, batch) != nil {
				t.Fatal("post-exit replay failed")
			}
			if observer.QueryRow(ctx, "SELECT ingested_seq FROM cheesetrap.processing_cursors").Scan(&cursor) != nil || cursor != before+2 {
				t.Fatal("post-exit replay sequence mismatch")
			}
		})
	}
}
