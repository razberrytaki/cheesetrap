//go:build integration

package ingestion

import (
	"cheesetrap/internal/observability"
	"cheesetrap/internal/store"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetentionCapacityRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	url := os.Getenv("CHEESETRAP_TEST_CAPACITY_COLLECTOR_URL")
	pool, e := store.NewPool(ctx, url)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	b := commitFixture(t, "20000000-0000-4000-8000-000000000711", 1)
	root := filepath.Dir(b.Generations[0].Path)
	source := testSource()
	source.SensorID = "10000000-0000-4000-8000-000000000711"
	source.Name = "capacity"
	source.Path = "cowrie.json"
	raw, _ := json.Marshal([]Source{source})
	manifest := filepath.Join(t.TempDir(), "sources.json")
	os.WriteFile(manifest, raw, 0600)
	os.WriteFile(filepath.Join(root, ".retention-loss.json"), []byte(`{"version":1,"sensors":{"10000000-0000-4000-8000-000000000711":3}}`), 0600)
	var recovered atomic.Bool
	probe := func(string) (uint64, uint64, error) {
		if recovered.Load() {
			return 100, 50, nil
		}
		return 100, 10, nil
	}
	runctx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- runCollector(runctx, url, root, manifest, probe) }()
	defer stop()
	wait := func(query string, want int) {
		t.Helper()
		for {
			var n int
			if pool.QueryRow(ctx, query, source.SensorID).Scan(&n) == nil && n == want {
				return
			}
			select {
			case err := <-done:
				t.Fatal("collector exit", err)
			case <-ctx.Done():
				t.Fatal("timeout", query)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	wait(`SELECT gap_count FROM cheesetrap.ingestion_gaps WHERE sensor_id=$1`, 4)
	var count int
	pool.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.events WHERE sensor_id=$1`, source.SensorID).Scan(&count)
	if count != 0 {
		t.Fatal("collected at 90%")
	}
	recovered.Store(true)
	wait(`SELECT count(*) FROM cheesetrap.events WHERE sensor_id=$1`, 1)
	wait(`SELECT count(*) FROM cheesetrap.sensors WHERE sensor_id=$1 AND state='active'`, 1)
	var causes []string
	if err := pool.QueryRow(ctx, `SELECT causes FROM cheesetrap.collection_gap_incidents WHERE sensor_id=$1`, source.SensorID).Scan(&causes); err != nil || len(causes) != 2 {
		t.Fatal("retention and storage causes missing", causes, err)
	}
	stop()
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatal(err)
	}
	var gaps int
	pool.QueryRow(ctx, `SELECT gap_count FROM cheesetrap.ingestion_gaps WHERE sensor_id=$1`, source.SensorID).Scan(&gaps)
	if gaps != 4 {
		t.Fatal("gap reset or receipt duplicate", gaps)
	}
	line, err := os.ReadFile(filepath.Join(root, "cowrie.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(root, "cowrie.json"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(line); err != nil {
		t.Fatal(err)
	}
	f.Close()
	runctx, stop = context.WithCancel(ctx)
	go func() { done <- runCollector(runctx, url, root, manifest, probe) }()
	wait(`SELECT count(*) FROM cheesetrap.events WHERE sensor_id=$1`, 2)
	wait(`SELECT count(*) FROM cheesetrap.events WHERE sensor_id=$1 AND NOT ('collection_gap'=ANY(quality_flags))`, 1)
	time.Sleep(300 * time.Millisecond)
	stop()
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatal(err)
	}
	pool.QueryRow(ctx, `SELECT gap_count FROM cheesetrap.ingestion_gaps WHERE sensor_id=$1`, source.SensorID).Scan(&gaps)
	if gaps != 4 {
		t.Fatal("restart reset or duplicate", gaps)
	}
	t.Run("cancellation_during_storage_probe", func(t *testing.T) {
		runctx, cancel := context.WithCancel(ctx)
		defer cancel()
		probe := func(string) (uint64, uint64, error) { cancel(); return 100, 50, nil }
		if err := runCollector(runctx, url, root, manifest, probe); err != context.Canceled {
			t.Fatalf("storage sample cancellation lost: %v", err)
		}
	})
	t.Run("storage_database_error_remains_failure", func(t *testing.T) {
		restricted, err := observability.SampleWithProbe(ctx, pool, "invalid-component", []string{root}, func(string) (uint64, uint64, error) { return 100, 50, nil })
		if !restricted || err != observability.ErrStatus {
			t.Fatalf("genuine storage error was lost: restricted=%v err=%v", restricted, err)
		}
	})

}

// A canceled SQL call must finish session cleanup before a local restart.
func TestCollectorCanceledQueryReleasesLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	url := os.Getenv("CHEESETRAP_TEST_CAPACITY_COLLECTOR_URL")
	observer, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	owner, err := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_CAPACITY_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "LOCK TABLE cheesetrap.sensors IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	b := commitFixture(t, "20000000-0000-4000-8000-000000000712", 1)
	root := filepath.Dir(b.Generations[0].Path)
	source := testSource()
	source.SensorID = "10000000-0000-4000-8000-000000000712"
	source.Name = "lease-cancellation"
	source.Path = "cowrie.json"
	data, err := json.Marshal([]Source{source})
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(t.TempDir(), "sources.json")
	if err := os.WriteFile(manifest, data, 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		runctx, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- runCollector(runctx, url, root, manifest, nil) }()
		ticker := time.NewTicker(time.Millisecond)
		for {
			var blocked bool
			err := observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks lease JOIN pg_locks waiting USING(pid) WHERE lease.locktype='advisory' AND lease.classid=1667781748 AND lease.objid=1 AND lease.granted AND lease.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT waiting.granted AND waiting.relation='cheesetrap.sensors'::regclass)`).Scan(&blocked)
			if err != nil {
				stop()
				ticker.Stop()
				<-done
				t.Fatal(err)
			}
			if blocked {
				break
			}
			select {
			case err := <-done:
				stop()
				ticker.Stop()
				t.Fatalf("collector exited before blocked query: %v", err)
			case <-ctx.Done():
				stop()
				ticker.Stop()
				<-done
				t.Fatal("collector never acquired lease and blocked")
			case <-ticker.C:
			}
		}
		ticker.Stop()
		stop()
		if err := <-done; err != context.Canceled {
			t.Fatalf("cancellation changed: %v", err)
		}
		var acquired bool
		if err := observer.QueryRow(ctx, "SELECT pg_try_advisory_lock(1667781748,1)").Scan(&acquired); err != nil {
			t.Fatal(err)
		}
		if !acquired {
			t.Fatalf("iteration %d: returned collector retained session lease after query cancellation", i)
		}
		if _, err := observer.Exec(ctx, "SELECT pg_advisory_unlock(1667781748,1)"); err != nil {
			t.Fatal(err)
		}
	}
}
