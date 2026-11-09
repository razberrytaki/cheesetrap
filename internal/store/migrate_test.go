//go:build integration

package store_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cheesetrap/internal/store"
	"cheesetrap/internal/store/db"
	"cheesetrap/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// This integration-only test is automatically discovered by the isolated runner.
// Missing runner credentials fail, never skip and accidentally report success.
func TestMigrationsAndRoles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	urls := map[string]string{}
	conns := map[string]*pgx.Conn{}
	for _, role := range []string{"migration", "api", "collector", "worker"} {
		url := os.Getenv("CHEESETRAP_TEST_EMPTY_" + strings.ToUpper(role) + "_URL")
		if url == "" {
			t.Fatal("isolated integration runner credentials required")
		}
		urls[role] = url
		c, err := pgx.Connect(ctx, url)
		if err != nil {
			t.Fatal("isolated role connection failed")
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		conns[role] = c
		var who string
		if err := c.QueryRow(ctx, "SELECT current_user").Scan(&who); err != nil || who != "cheesetrap_"+role {
			t.Fatal("role authentication mismatch")
		}
	}
	migration := conns["migration"]
	var count int
	if err := migration.QueryRow(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'cheesetrap'").Scan(&count); err != nil || count != 0 {
		t.Fatal("database must start empty")
	}
	migrateConcurrently := func(t *testing.T) {
		t.Helper()
		var wg sync.WaitGroup
		failures := make(chan error, 3)
		for range 3 {
			wg.Add(1)
			go func() { defer wg.Done(); failures <- store.Migrate(ctx, urls["migration"]) }()
		}
		wg.Wait()
		close(failures)
		for err := range failures {
			if err != nil {
				t.Fatal("concurrent migrations failed")
			}
		}
	}
	sqlDB := stdlib.OpenDB(*migration.Config())
	defer sqlDB.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.Files, goose.WithTableName("cheesetrap.goose_db_version"), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 30); err != nil {
		t.Fatal(err)
	}
	const legacySensor = "10000000-0000-4000-8000-000000000031"
	if _, err := migration.Exec(ctx, `INSERT INTO cheesetrap.sensors(sensor_id,name,engine,public_ip,public_port) VALUES($1,'legacy-gap','cowrie','192.0.2.1',22);
 `, legacySensor); err != nil {
		t.Fatal(err)
	}
	if _, err := migration.Exec(ctx, `INSERT INTO cheesetrap.ingestion_gaps(sensor_id,started_at,observed_through,gap_count) VALUES($1,'2000-01-01','2000-01-02',7)`, legacySensor); err != nil {
		t.Fatal(err)
	}
	t.Run("empty_database_concurrent_migrations", migrateConcurrently)
	// The first RED must reach a real PostgreSQL server and fail on absent schema.
	if err := migration.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.events").Scan(&count); err != nil {
		t.Fatal("migration did not create events table")
	}
	if count != 0 {
		t.Fatal("new events table is not empty")
	}
	var ingested, detected int64
	if err := migration.QueryRow(ctx, "SELECT ingested_seq,detected_seq FROM cheesetrap.processing_cursors WHERE singleton").Scan(&ingested, &detected); err != nil || ingested != 0 || detected != 0 {
		t.Fatal("fresh migration-test database cursors must start at zero")
	}
	t.Run("legacy_gap_backfill", func(t *testing.T) {
		var exists bool
		if err := migration.QueryRow(ctx, `SELECT to_regclass('cheesetrap.collection_gap_incidents') IS NOT NULL`).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatal("dated collection-gap history is missing")
		}
		var valid bool
		if err := migration.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(started_at='2000-01-01'::timestamptz AND observed_through='2000-01-02'::timestamptz AND gap_count=7 AND causes=ARRAY['legacy']) FROM cheesetrap.collection_gap_incidents WHERE sensor_id=$1`, legacySensor).Scan(&valid); err != nil || !valid {
			t.Fatal("legacy incident range, count, or cause lost", err)
		}
	})
	t.Run("idempotent_concurrent_migrations", func(t *testing.T) {
		migrateConcurrently(t)
		if err := migration.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.goose_db_version WHERE is_applied AND version_id > 0").Scan(&count); err != nil || count != 31 {
			t.Fatal("migration history is not idempotent")
		}
	})
	run := func(t *testing.T, role, query string, args ...any) {
		t.Helper()
		if _, err := conns[role].Exec(ctx, query, args...); err != nil {
			t.Fatalf("%s allowed SQL failed (state %s)", role, sqlState(err))
		}
	}
	reject := func(t *testing.T, role, state, query string, args ...any) {
		t.Helper()
		_, err := conns[role].Exec(ctx, query, args...)
		if sqlState(err) != state {
			t.Fatalf("%s forbidden SQL state = %s; want %s", role, sqlState(err), state)
		}
	}
	t.Run("membership_view_least_privilege", func(t *testing.T) {
		for _, role := range []string{"api", "worker"} {
			run(t, role, "SELECT * FROM cheesetrap.detection_evidence_membership")
		}
		reject(t, "collector", "42501", "SELECT * FROM cheesetrap.detection_evidence_membership")
		for _, role := range []string{"api", "worker", "collector"} {
			var allowed bool
			if err := conns[role].QueryRow(ctx, "SELECT has_table_privilege(current_user,'cheesetrap.detection_evidence_membership','INSERT,UPDATE,DELETE,TRUNCATE')").Scan(&allowed); err != nil || allowed {
				t.Fatal("membership view permits runtime mutation", role, err)
			}
		}
	})
	t.Run("river_history_and_least_privilege", func(t *testing.T) {
		if err := migration.QueryRow(ctx, "SELECT count(*) FROM cheesetrap_river.river_migration WHERE line='main' AND version BETWEEN 1 AND 8").Scan(&count); err != nil || count != 8 {
			t.Fatal("official River history incomplete")
		}
		run(t, "worker", "SELECT cheesetrap_river.river_job_state_in_bitmask(B'11111111','available')")
		for _, role := range []string{"collector"} {
			reject(t, role, "42501", "SELECT * FROM cheesetrap_river.river_job")
			reject(t, role, "42501", "SELECT cheesetrap_river.river_job_state_in_bitmask(B'11111111','available')")
			reject(t, role, "42501", "UPDATE cheesetrap.processing_cursors SET sealed_before=clock_timestamp()")
			reject(t, role, "42501", "INSERT INTO cheesetrap.reporting_schedule_versions(timezone,period_days,effective_from) VALUES('UTC',1,clock_timestamp())")
		}
		for _, role := range []string{"api", "collector", "worker"} {
			reject(t, role, "42501", "CREATE TABLE cheesetrap_river.forbidden(id int)")
			reject(t, role, "42501", "TRUNCATE cheesetrap_river.river_job")
			reject(t, role, "42501", "INSERT INTO cheesetrap_river.river_migration(line,version) VALUES('main',99)")
		}
		run(t, "api", "SELECT * FROM cheesetrap_river.river_job")
		for _, sql := range []string{"DELETE FROM cheesetrap_river.river_job", "UPDATE cheesetrap_river.river_job SET state='cancelled'", "SELECT * FROM cheesetrap_river.river_leader", "SELECT * FROM cheesetrap_river.river_queue", "UPDATE cheesetrap.processing_cursors SET ingested_seq=1"} {
			reject(t, "api", "42501", sql)
		}
		for _, table := range []string{"contact_refresh_requests", "review_idempotency", "rule_config_versions", "reports", "report_revisions"} {
			reject(t, "collector", "42501", "SELECT * FROM cheesetrap."+table)
		}
		reject(t, "worker", "42501", "UPDATE cheesetrap.reporting_schedule_versions SET timezone='Asia/Tokyo'")
		reject(t, "worker", "42501", "DELETE FROM cheesetrap.report_windows")
		reject(t, "worker", "42501", "UPDATE cheesetrap.report_windows SET end_at=clock_timestamp()")
	})
	t.Run("function_execution_defaults", func(t *testing.T) {
		run(t, "migration", "CREATE FUNCTION cheesetrap.test_execution_default() RETURNS integer LANGUAGE sql AS 'SELECT 1'")
		defer run(t, "migration", "DROP FUNCTION cheesetrap.test_execution_default()")
		run(t, "migration", "SELECT cheesetrap.test_execution_default()")
		for _, role := range []string{"api", "collector", "worker"} {
			reject(t, role, "42501", "SELECT cheesetrap.test_execution_default()")
		}
	})
	sensor := "10000000-0000-4000-8000-000000000001"
	generation := "20000000-0000-4000-8000-000000000001"
	admin := "30000000-0000-4000-8000-000000000001"
	event := `INSERT INTO cheesetrap.events (sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,source_ip,source_port,destination_ip,destination_port,service,event_type,attributes,raw_hash) VALUES ($1,$2,$3,$4,1,'cowrie','2001:db8::1',12345,'192.0.2.1',22,'ssh','login.failed','{}',repeat('a',64))`
	t.Run("collector_allowed", func(t *testing.T) {
		run(t, "collector", "INSERT INTO cheesetrap.sensors (sensor_id,name,engine) VALUES ($1,'test','cowrie')", sensor)
		run(t, "collector", "UPDATE cheesetrap.sensors SET name='renamed',engine_version='3.1.2',config_version=2,public_ip='192.0.2.1',public_port=22,state='active' WHERE sensor_id=$1", sensor)
		run(t, "collector", "INSERT INTO cheesetrap.file_generations (file_generation_id,sensor_id,path,device,inode) VALUES ($1,$2,'/logs/engine.jsonl',1,2)", generation, sensor)
		run(t, "collector", "UPDATE cheesetrap.file_generations SET closed_at=now() WHERE file_generation_id=$1", generation)
		run(t, "collector", "INSERT INTO cheesetrap.checkpoints (sensor_id,file_generation_id,byte_offset) VALUES ($1,$2,0)", sensor, generation)
		run(t, "collector", event, sensor, generation, 0, 1)
		run(t, "collector", "UPDATE cheesetrap.checkpoints SET byte_offset=100 WHERE file_generation_id=$1", generation)
		run(t, "collector", "UPDATE cheesetrap.processing_cursors SET ingested_seq=1 WHERE singleton")
		run(t, "collector", "SELECT * FROM cheesetrap.events")
	})
	t.Run("collector_metadata_permissions", func(t *testing.T) {
		run(t, "collector", "INSERT INTO cheesetrap.ingestion_rejections(sensor_id,file_generation_id,byte_offset,byte_end_offset,byte_count,raw_hash,reason) VALUES($1,$2,200,204,3,repeat('c',64),'invalid_json')", sensor, generation)
		run(t, "collector", "INSERT INTO cheesetrap.ingestion_gaps(sensor_id,started_at,observed_through) VALUES($1,clock_timestamp(),clock_timestamp())", sensor)
		run(t, "collector", "UPDATE cheesetrap.ingestion_gaps SET observed_through=clock_timestamp() WHERE sensor_id=$1", sensor)
		for _, role := range []string{"api", "collector", "worker"} {
			run(t, role, "SELECT * FROM cheesetrap.ingestion_rejections")
			run(t, role, "SELECT * FROM cheesetrap.ingestion_gaps")
			for _, query := range []string{"UPDATE cheesetrap.ingestion_rejections SET reason='adapter_rejected'", "DELETE FROM cheesetrap.ingestion_rejections", "TRUNCATE cheesetrap.ingestion_rejections", "DELETE FROM cheesetrap.ingestion_gaps", "TRUNCATE cheesetrap.ingestion_gaps", "ALTER TABLE cheesetrap.ingestion_rejections ADD COLUMN forbidden int"} {
				reject(t, role, "42501", query)
			}
		}
		for _, role := range []string{"api", "worker"} {
			reject(t, role, "42501", "UPDATE cheesetrap.ingestion_gaps SET observed_through=clock_timestamp()")
			reject(t, role, "42501", "INSERT INTO cheesetrap.ingestion_gaps(sensor_id,started_at,observed_through) VALUES($1,clock_timestamp(),clock_timestamp())", sensor)
			reject(t, role, "42501", "INSERT INTO cheesetrap.ingestion_rejections(sensor_id,file_generation_id,byte_offset,byte_end_offset,byte_count,raw_hash,reason) VALUES($1,$2,204,208,3,repeat('c',64),'invalid_json')", sensor, generation)
		}
		reject(t, "collector", "23514", "UPDATE cheesetrap.file_generations SET fingerprint_bytes=4097")
		reject(t, "collector", "23514", "UPDATE cheesetrap.file_generations SET observed_size=-1")
	})

	t.Run("incident_writer_and_permissions", func(t *testing.T) {
		note := "SELECT cheesetrap.note_collection_gap($1,clock_timestamp(),$2,$3)"
		run(t, "collector", note, sensor, "source_change", int64(2))
		run(t, "collector", note, sensor, "retention_cleanup", int64(3))
		var valid bool
		if err := migration.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(gap_count=5 AND causes=ARRAY['retention_cleanup','source_change']) FROM cheesetrap.collection_gap_incidents WHERE sensor_id=$1`, sensor).Scan(&valid); err != nil || !valid {
			t.Fatal("nearby causes did not merge", err)
		}
		run(t, "migration", `UPDATE cheesetrap.collection_gap_incidents SET started_at=clock_timestamp()-interval '12 minutes',observed_through=clock_timestamp()-interval '11 minutes' WHERE sensor_id=$1`, sensor)
		run(t, "collector", note, sensor, "storage_restricted", int64(1))
		if err := migration.QueryRow(ctx, `SELECT count(*)=2 FROM cheesetrap.collection_gap_incidents WHERE sensor_id=$1`, sensor).Scan(&valid); err != nil || !valid {
			t.Fatal("separate incident was lost", err)
		}
		for _, role := range []string{"api", "collector", "worker"} {
			run(t, role, "SELECT * FROM cheesetrap.collection_gap_incidents")
			reject(t, role, "42501", "DELETE FROM cheesetrap.collection_gap_incidents")
			reject(t, role, "42501", "TRUNCATE cheesetrap.collection_gap_incidents")
		}
		for _, role := range []string{"api", "worker"} {
			reject(t, role, "42501", note, sensor, "source_change", int64(1))
			reject(t, role, "42501", "UPDATE cheesetrap.collection_gap_incidents SET gap_count=0")
			reject(t, role, "42501", `INSERT INTO cheesetrap.collection_gap_incidents(sensor_id,started_at,observed_through,causes) VALUES($1,now(),now(),ARRAY['legacy'])`, sensor)
		}
		reject(t, "collector", "23514", `INSERT INTO cheesetrap.collection_gap_incidents(sensor_id,started_at,observed_through,causes) VALUES($1,now(),now(),ARRAY['unknown'])`, sensor)
	})
	t.Run("schema_invariants", func(t *testing.T) {
		reject(t, "collector", "23514", "UPDATE cheesetrap.sensors SET config_version=0")
		reject(t, "collector", "23514", "UPDATE cheesetrap.sensors SET public_port=65536")
		reject(t, "collector", "23514", "UPDATE cheesetrap.sensors SET public_ip='192.0.2.1/24'")
		if err := migration.QueryRow(ctx, "SELECT count(*) FROM pg_indexes WHERE schemaname='cheesetrap' AND indexname='events_service_time_idx'").Scan(&count); err != nil || count != 1 {
			t.Fatal("service/time lookup index missing")
		}
		reject(t, "collector", "23505", event, sensor, generation, 0, 2)
		reject(t, "collector", "23505", event, sensor, generation, 100, 1)
		reject(t, "collector", "23514", event, sensor, generation, 100, 0)
		reject(t, "collector", "23514", event, sensor, generation, -1, 2)
		other := "10000000-0000-4000-8000-000000000002"
		run(t, "collector", "INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES ($1,'other','opencanary')", other)
		reject(t, "collector", "23503", event, other, generation, 200, 2)
		reject(t, "collector", "23503", "INSERT INTO cheesetrap.checkpoints(sensor_id,file_generation_id,byte_offset) VALUES($1,$2,0)", other, generation)
		reject(t, "collector", "23514", "UPDATE cheesetrap.checkpoints SET byte_offset=-1")
		reject(t, "collector", "23514", "UPDATE cheesetrap.processing_cursors SET ingested_seq=-1")
		reject(t, "worker", "23514", "UPDATE cheesetrap.processing_cursors SET detected_seq=2")
		reject(t, "worker", "23514", "UPDATE cheesetrap.processing_cursors SET detected_seq=-1")
		var observed *time.Time
		var source string
		var eventID string
		if err := migration.QueryRow(ctx, "SELECT observed_at,host(source_ip),event_id::text FROM cheesetrap.events").Scan(&observed, &source, &eventID); err != nil || observed != nil || source != "2001:db8::1" || eventID == "" {
			t.Fatal("nullable timestamp, inet, or generated UUID mismatch")
		}
		reject(t, "migration", "23514", "INSERT INTO cheesetrap.processing_cursors(singleton) VALUES(false)")
		reject(t, "migration", "23505", "INSERT INTO cheesetrap.processing_cursors(singleton) VALUES(true)")
	})
	t.Run("api_allowed", func(t *testing.T) {
		run(t, "api", "SELECT * FROM cheesetrap.events JOIN cheesetrap.sensors USING(sensor_id)")
		run(t, "api", "INSERT INTO cheesetrap.admins(admin_id,username,password_hash) VALUES($1,'admin','argon2id-test-hash')", admin)
		reject(t, "api", "23505", "INSERT INTO cheesetrap.admins(username,password_hash) VALUES('second','hash')")
		run(t, "api", "UPDATE cheesetrap.admins SET password_hash='replacement-hash' WHERE admin_id=$1", admin)
		run(t, "api", "INSERT INTO cheesetrap.sessions(token_hash,admin_id,expires_at) VALUES(repeat('b',64),$1,now()+interval '1 hour')", admin)
		run(t, "api", "SELECT token_hash,password_hash FROM cheesetrap.sessions JOIN cheesetrap.admins USING(admin_id)")
		run(t, "api", "UPDATE cheesetrap.sessions SET expires_at=now()+interval '2 hours',last_seen_at=now()")
		reject(t, "api", "23514", "UPDATE cheesetrap.sessions SET last_seen_at=created_at-interval '1 second'")
		run(t, "api", "DELETE FROM cheesetrap.sessions")
		run(t, "api", "INSERT INTO cheesetrap.settings(key,version,value) VALUES('reporting',1,'{}')")
		run(t, "api", "UPDATE cheesetrap.settings SET version=version+1,value='{\"enabled\":false}' WHERE key='reporting'")
		run(t, "api", "SELECT * FROM cheesetrap.settings")
		reject(t, "api", "23514", "UPDATE cheesetrap.settings SET version=0")
		run(t, "api", "INSERT INTO cheesetrap.audit(admin_id,action,details) VALUES($1,'settings.updated','{}')", admin)
		run(t, "api", "SELECT * FROM cheesetrap.audit")
	})
	t.Run("worker_allowed", func(t *testing.T) {
		run(t, "worker", "SELECT * FROM cheesetrap.events JOIN cheesetrap.sensors USING(sensor_id)")
		run(t, "worker", "UPDATE cheesetrap.processing_cursors SET detected_seq=1 WHERE singleton")
		reject(t, "collector", "23514", "UPDATE cheesetrap.processing_cursors SET ingested_seq=0")
	})

	t.Run("detection_roles_and_immutability", func(t *testing.T) {
		run(t, "worker", "INSERT INTO cheesetrap.detection_completions(ingestion_seq,event_id,rule_set_version) SELECT ingestion_seq,event_id,'1' FROM cheesetrap.events WHERE ingestion_seq=1")
		run(t, "worker", `INSERT INTO cheesetrap.detection_results(rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation) SELECT 'SSH-REPEAT','1',event_id,ingestion_seq,'2001:db8::1',now()-interval '10 minutes',now(),repeat('d',64),1,false,true,'{}' FROM cheesetrap.events WHERE ingestion_seq=1`)
		run(t, "worker", "INSERT INTO cheesetrap.detection_evidence(detection_id,event_id) SELECT detection_id,processing_event_id FROM cheesetrap.detection_results")
		for _, table := range []string{"detection_completions", "detection_results", "detection_evidence"} {
			for _, role := range []string{"api", "worker"} {
				run(t, role, "SELECT * FROM cheesetrap."+table)
			}
			reject(t, "collector", "42501", "SELECT * FROM cheesetrap."+table)
			for _, role := range []string{"api", "collector", "worker"} {
				reject(t, role, "42501", "DELETE FROM cheesetrap."+table)
				reject(t, role, "42501", "TRUNCATE cheesetrap."+table)
				reject(t, role, "42501", "ALTER TABLE cheesetrap."+table+" ADD COLUMN forbidden int")
			}
			for _, role := range []string{"api", "collector"} {
				reject(t, role, "42501", "INSERT INTO cheesetrap."+table+" DEFAULT VALUES")
			}
		}
		for _, role := range []string{"api", "collector", "worker"} {
			reject(t, role, "42501", "UPDATE cheesetrap.detection_completions SET rule_set_version='tampered'")
			reject(t, role, "42501", "UPDATE cheesetrap.detection_results SET evidence_eligible=true")
			reject(t, role, "42501", "UPDATE cheesetrap.detection_evidence SET event_id=event_id")
		}
		reject(t, "worker", "23505", "INSERT INTO cheesetrap.detection_evidence SELECT * FROM cheesetrap.detection_evidence")
		reject(t, "worker", "23503", "INSERT INTO cheesetrap.detection_completions(ingestion_seq,event_id,rule_set_version) VALUES(2,'00000000-0000-4000-8000-000000000001','1')")
	})
	for _, role := range []string{"api", "collector", "worker"} {
		t.Run(role+"_denied", func(t *testing.T) {
			for _, query := range []string{
				"CREATE TABLE cheesetrap.forbidden(id int)", "CREATE TABLE public.forbidden(id int)", "CREATE TEMP TABLE forbidden(id int)",
				"CREATE SCHEMA forbidden", "ALTER TABLE cheesetrap.events ADD COLUMN forbidden text", "DROP TABLE cheesetrap.events",
				"TRUNCATE cheesetrap.events", "UPDATE cheesetrap.events SET engine='tampered'", "DELETE FROM cheesetrap.events",
				"TRUNCATE cheesetrap.sensors", "TRUNCATE cheesetrap.file_generations", "TRUNCATE cheesetrap.checkpoints",
				"TRUNCATE cheesetrap.admins", "TRUNCATE cheesetrap.sessions", "TRUNCATE cheesetrap.settings", "TRUNCATE cheesetrap.processing_cursors",
				"UPDATE cheesetrap.audit SET action='tampered'", "DELETE FROM cheesetrap.audit", "TRUNCATE cheesetrap.audit",
				"SET ROLE cheesetrap_migration", "ALTER ROLE CURRENT_USER SUPERUSER", "CREATE ROLE forbidden", "SELECT * FROM cheesetrap.goose_db_version",
			} {
				reject(t, role, "42501", query)
			}
			if err := store.Migrate(ctx, urls[role]); err == nil {
				t.Error("runtime account migrated")
			}
		})
	}
	t.Run("cross_role_denied", func(t *testing.T) {
		for _, role := range []string{"collector", "worker"} {
			reject(t, role, "42501", "SELECT password_hash FROM cheesetrap.admins")
			reject(t, role, "42501", "SELECT token_hash FROM cheesetrap.sessions")
			reject(t, role, "42501", "INSERT INTO cheesetrap.settings(key,version,value) VALUES('forbidden',1,'{}')")
			if role == "collector" {
				reject(t, role, "42501", "INSERT INTO cheesetrap.audit(action,details) VALUES('forbidden','{}')")
			}
		}
		reject(t, "api", "42501", event, sensor, generation, 200, 2)
		reject(t, "worker", "42501", event, sensor, generation, 200, 2)
		reject(t, "api", "42501", "UPDATE cheesetrap.processing_cursors SET ingested_seq=2")
		reject(t, "api", "42501", "UPDATE cheesetrap.processing_cursors SET detected_seq=0")
		reject(t, "worker", "42501", "UPDATE cheesetrap.processing_cursors SET ingested_seq=2")
		reject(t, "collector", "42501", "UPDATE cheesetrap.processing_cursors SET detected_seq=0")
		reject(t, "collector", "42501", "DELETE FROM cheesetrap.checkpoints")
	})
	t.Run("pool_and_generated_queries", func(t *testing.T) {
		for _, role := range []string{"collector", "worker"} {
			pool, err := store.NewPool(ctx, urls[role]+"&search_path=public&pool_max_conns=200&pool_min_idle_conns=20")
			if err != nil {
				t.Fatal("runtime pool failed")
			}
			if pool.Config().MaxConns != 4 || pool.Config().MinIdleConns != 0 {
				pool.Close()
				t.Fatal("pool is unbounded")
			}
			var path string
			if err := pool.QueryRow(ctx, "SHOW search_path").Scan(&path); err != nil || path != "pg_catalog,cheesetrap" {
				pool.Close()
				t.Fatal("unsafe search path")
			}
			tx, err := pool.Begin(ctx)
			if err != nil {
				pool.Close()
				t.Fatal("begin failed")
			}
			q := db.New(pool).WithTx(tx)
			cursors, err := q.LockProcessingCursors(ctx)
			if err != nil || cursors.IngestedSeq != 1 || cursors.DetectedSeq != 1 {
				_ = tx.Rollback(ctx)
				pool.Close()
				t.Fatal("generated cursor lock query failed")
			}
			events, err := q.ListEventsAfterSequence(ctx, db.ListEventsAfterSequenceParams{IngestionSeq: 0, Limit: 10})
			if err != nil || len(events) != 1 || events[0].ObservedAt.Valid || events[0].SourceIp == nil || events[0].SourceIp.String() != "2001:db8::1" {
				_ = tx.Rollback(ctx)
				pool.Close()
				t.Fatal("generated event query/type mapping failed")
			}
			if err := tx.Rollback(ctx); err != nil {
				pool.Close()
				t.Fatal("rollback failed")
			}
			pool.Close()
		}
		q := db.New(conns["api"])
		setting, err := q.GetSetting(ctx, "reporting")
		if err != nil || setting.Version != 2 {
			t.Fatal("generated settings query failed")
		}
		if _, err := q.LockProcessingCursors(ctx); err != nil {
			t.Fatal("API cannot lock cursor for atomic settings boundary")
		}
		// The standard database is already migrated for other integration packages.
		prepared, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_API_URL"))
		if err != nil {
			t.Fatal("prepared test database connection failed")
		}
		defer prepared.Close()
		cursors, err := db.New(prepared).GetProcessingCursors(ctx)
		if err != nil || cursors.IngestedSeq < 0 || cursors.DetectedSeq < 0 || cursors.DetectedSeq > cursors.IngestedSeq {
			t.Fatal("normal integration database was not prepared separately")
		}
	})
	t.Run("cli_embedded_migrations", func(t *testing.T) {
		root := filepath.Clean(filepath.Join("..", ".."))
		binary := filepath.Join(t.TempDir(), "cheesetrap")
		build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/cheesetrap")
		build.Dir = root
		if _, err := build.CombinedOutput(); err != nil {
			t.Fatal("CLI build failed")
		}
		for _, role := range []string{"migration", "api"} {
			cmd := exec.CommandContext(ctx, binary, "migrate")
			cmd.Dir = t.TempDir()
			cmd.Env = []string{"CHEESETRAP_DATABASE_URL=" + urls[role]}
			out, err := cmd.CombinedOutput()
			if (role == "migration") != (err == nil) {
				t.Fatalf("%s CLI migration exit mismatch", role)
			}
			if strings.Contains(string(out), urls[role]) || strings.Contains(string(out), "postgresql://") || strings.Contains(string(out), "password") || strings.Contains(string(out), "ERROR:") {
				t.Fatal("CLI leaked database details")
			}
			if role == "api" && !strings.Contains(string(out), `"error_code":"runtime_failure"`) {
				t.Fatal("CLI failure missing static code")
			}
		}
	})
}

func sqlState(err error) string {
	if err == nil {
		return "success"
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		return pgerr.Code
	}
	return "non-postgres-error"
}
