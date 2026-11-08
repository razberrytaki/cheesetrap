//go:build integration

package ingestion

import (
	"bytes"
	"cheesetrap/internal/store"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCollector(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_COLLECTOR_URL"))
	if err != nil {
		t.Fatal("isolated collector database required")
	}
	defer pool.Close()
	b := commitFixture(t, "20000000-0000-4000-8000-000000000201", 1)
	root := filepath.Dir(b.Generations[0].Path)
	source := testSource()
	source.SensorID = "10000000-0000-4000-8000-000000000201"
	source.Name = "runtime-sensor"
	source.Path = "cowrie.json"
	data, _ := json.Marshal([]Source{source})
	manifest := filepath.Join(t.TempDir(), "sources.json")
	if os.WriteFile(manifest, data, 0600) != nil {
		t.Fatal("fixture manifest write")
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- RunCollector(runCtx, os.Getenv("CHEESETRAP_TEST_COLLECTOR_URL"), root, manifest) }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("collector never persisted evidence")
		case err := <-done:
			t.Fatalf("collector returned before collection: %v", err)
		case <-ticker.C:
		}
		var count int
		if pool.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.events WHERE sensor_id=$1", source.SensorID).Scan(&count) == nil && count == 1 {
			break
		}
	}
	// A second collector cannot create a competing generation UUID.
	if err := RunCollector(ctx, os.Getenv("CHEESETRAP_TEST_COLLECTOR_URL"), root, manifest); err == nil {
		t.Fatal("concurrent collector ownership accepted")
	}
	stop()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatal("collector shutdown failed")
		}
	case <-ctx.Done():
		t.Fatal("collector shutdown timeout")
	}
	// Restart must reuse the saved generation and checkpoint, including at EOF.
	restarted, halt := context.WithCancel(ctx)
	again := make(chan error, 1)
	go func() { again <- RunCollector(restarted, os.Getenv("CHEESETRAP_TEST_COLLECTOR_URL"), root, manifest) }()
	var updated time.Time
	if pool.QueryRow(ctx, "SELECT updated_at FROM cheesetrap.checkpoints WHERE sensor_id=$1", source.SensorID).Scan(&updated) != nil {
		t.Fatal("checkpoint missing")
	}
	for {
		select {
		case <-ctx.Done():
			t.Fatal("restart never resumed")
		case err := <-again:
			t.Fatalf("restart returned: %v", err)
		case <-ticker.C:
		}
		var newer time.Time
		if pool.QueryRow(ctx, "SELECT updated_at FROM cheesetrap.checkpoints WHERE sensor_id=$1", source.SensorID).Scan(&newer) == nil && newer.After(updated) {
			break
		}
	}
	halt()
	<-again
	var events, generations int
	if pool.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.events WHERE sensor_id=$1", source.SensorID).Scan(&events) != nil || events != 1 {
		t.Fatal("restart duplicated event")
	}
	if pool.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.file_generations WHERE sensor_id=$1", source.SensorID).Scan(&generations) != nil || generations != 1 {
		t.Fatal("restart duplicated generation")
	}
	t.Run("restart_loss_preserves_downtime_interval", func(t *testing.T) {
		var marker time.Time
		if pool.QueryRow(ctx, "SELECT updated_at FROM cheesetrap.checkpoints WHERE sensor_id=$1", source.SensorID).Scan(&marker) != nil {
			t.Fatal("durable observation marker missing")
		}
		if os.Remove(filepath.Join(root, "cowrie.json")) != nil {
			t.Fatal("remove stopped source fixture")
		}
		missingCtx, end := context.WithCancel(ctx)
		lost := make(chan error, 1)
		go func() { lost <- RunCollector(missingCtx, os.Getenv("CHEESETRAP_TEST_COLLECTOR_URL"), root, manifest) }()
		defer end()
		var started time.Time
		for {
			select {
			case <-ctx.Done():
				t.Fatal("missing source gap not persisted")
			case err := <-lost:
				t.Fatalf("missing-source collector exited: %v", err)
			case <-ticker.C:
			}
			if pool.QueryRow(ctx, "SELECT started_at FROM cheesetrap.ingestion_gaps WHERE sensor_id=$1", source.SensorID).Scan(&started) == nil {
				break
			}
		}
		end()
		<-lost
		if started.After(marker) {
			t.Fatal("gap omitted downtime after previous durable collection observation")
		}
		var closed int
		if pool.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.file_generations WHERE sensor_id=$1 AND closed_at IS NOT NULL", source.SensorID).Scan(&closed) != nil || closed != 1 {
			t.Fatal("unavailable generation not durably closed")
		}
	})

}

func TestCollectorCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "cheesetrap")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/cheesetrap")
	build.Dir = filepath.Join("..", "..")
	if _, err := build.CombinedOutput(); err != nil {
		t.Fatal("collector CLI build failed")
	}
	batch := commitFixture(t, "20000000-0000-4000-8000-000000000202", 1)
	root := filepath.Dir(batch.Generations[0].Path)
	source := testSource()
	source.SensorID = "10000000-0000-4000-8000-000000000202"
	source.Name = "cli-sensor"
	manifest := filepath.Join(t.TempDir(), "sources.json")
	data, _ := json.Marshal([]Source{source})
	if os.WriteFile(manifest, data, 0600) != nil {
		t.Fatal("CLI manifest fixture")
	}
	command := exec.CommandContext(ctx, binary, "collector")
	command.Env = []string{"CHEESETRAP_DATABASE_URL=" + os.Getenv("CHEESETRAP_TEST_COLLECTOR_URL"), "CHEESETRAP_COLLECTOR_LOG_DIR=" + root, "CHEESETRAP_COLLECTOR_SOURCES_FILE=" + manifest, "CHEESETRAP_SHUTDOWN_GRACE=2s"}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if command.Start() != nil {
		t.Fatal("collector CLI start failed")
	}
	defer command.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	observer, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_COLLECTOR_URL"))
	if err != nil {
		t.Fatal("CLI observation connection")
	}
	defer observer.Close(ctx)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("CLI collection timeout")
		case <-done:
			t.Fatal("CLI returned before collection")
		case <-ticker.C:
		}
		var count int
		if observer.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.events WHERE sensor_id=$1", source.SensorID).Scan(&count) == nil && count == 1 {
			break
		}
	}
	if command.Process.Signal(syscall.SIGTERM) != nil {
		t.Fatal("CLI termination signal failed")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("CLI did not exit successfully after SIGTERM")
		}
	case <-ctx.Done():
		t.Fatal("CLI shutdown timeout")
	}
	if strings.Contains(output.String(), "postgresql://") || !strings.Contains(output.String(), "role_completed") {
		t.Fatal("CLI output leaked database URL or missed graceful completion")
	}
	var lease bool
	if observer.QueryRow(ctx, "SELECT pg_try_advisory_lock(1667781748,1)").Scan(&lease) != nil || !lease {
		t.Fatal("CLI shutdown retained collector lease")
	}
	_, _ = observer.Exec(ctx, "SELECT pg_advisory_unlock(1667781748,1)")
}

func TestCollectorRetriesUncommittedBatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_MIGRATION_URL"))
	if err != nil {
		t.Fatal("retry fixture owner connection")
	}
	defer owner.Close(ctx)
	_, err = owner.Exec(ctx, `CREATE SEQUENCE cheesetrap.test_collector_attempts; CREATE FUNCTION cheesetrap.test_collector_retry() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$ BEGIN IF nextval('cheesetrap.test_collector_attempts')=1 THEN RAISE EXCEPTION 'test interruption'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_collector_retry BEFORE INSERT OR UPDATE ON cheesetrap.checkpoints FOR EACH ROW EXECUTE FUNCTION cheesetrap.test_collector_retry()`)
	if err != nil {
		t.Fatal("retry trigger fixture")
	}
	defer owner.Exec(context.Background(), "DROP TRIGGER test_collector_retry ON cheesetrap.checkpoints; DROP FUNCTION cheesetrap.test_collector_retry(); DROP SEQUENCE cheesetrap.test_collector_attempts")
	batch := commitFixture(t, "20000000-0000-4000-8000-000000000203", 1)
	root := filepath.Dir(batch.Generations[0].Path)
	source := testSource()
	source.SensorID = "10000000-0000-4000-8000-000000000203"
	source.Name = "retry-sensor"
	manifest := filepath.Join(t.TempDir(), "sources.json")
	data, _ := json.Marshal([]Source{source})
	if os.WriteFile(manifest, data, 0600) != nil {
		t.Fatal("retry manifest fixture")
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- RunCollector(runCtx, os.Getenv("CHEESETRAP_TEST_COLLECTOR_URL"), root, manifest) }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("retry never committed")
		case <-done:
			t.Fatal("collector did not retain pending batch")
		case <-ticker.C:
		}
		var count int
		if owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.events WHERE sensor_id=$1", source.SensorID).Scan(&count) == nil && count == 1 {
			break
		}
	}
	stop()
	<-done
	var flags []string
	var attempts, offset int64
	var generations int
	if owner.QueryRow(ctx, "SELECT quality_flags FROM cheesetrap.events WHERE sensor_id=$1", source.SensorID).Scan(&flags) != nil || !slices.Contains(flags, "collection_gap") {
		t.Fatal("retry gap omitted from event")
	}
	if owner.QueryRow(ctx, "SELECT last_value FROM cheesetrap.test_collector_attempts").Scan(&attempts) != nil || attempts < 2 {
		t.Fatal("database failure not exercised")
	}
	if owner.QueryRow(ctx, "SELECT byte_offset FROM cheesetrap.checkpoints WHERE sensor_id=$1", source.SensorID).Scan(&offset) != nil || offset != batch.Records[0].EndOffset {
		t.Fatal("retry checkpoint lost uncommitted bytes")
	}
	if owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.file_generations WHERE sensor_id=$1", source.SensorID).Scan(&generations) != nil || generations != 1 {
		t.Fatal("retry replaced pending generation")
	}
	var state string
	if owner.QueryRow(ctx, "SELECT state FROM cheesetrap.sensors JOIN cheesetrap.ingestion_gaps USING(sensor_id) WHERE sensor_id=$1", source.SensorID).Scan(&state) != nil || state != "degraded" {
		t.Fatal("retry sensor gap not durable")
	}
}
