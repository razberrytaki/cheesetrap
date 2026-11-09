//go:build integration

package store_test

import (
	"cheesetrap/internal/store"
	"cheesetrap/migrations"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEvidenceChunkStorage(t *testing.T) {
	ctx := context.Background()
	connect := func(role string) *pgx.Conn {
		t.Helper()
		c, e := pgx.Connect(ctx, os.Getenv("CHEESETRAP_TEST_CHUNKS_"+role+"_URL"))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { c.Close(ctx) })
		return c
	}
	owner, worker := connect("MIGRATION"), connect("WORKER")
	provider, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDB(*owner.Config()), migrations.Files, goose.WithTableName("cheesetrap.goose_db_version"), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if _, err = provider.UpTo(ctx, 14); err != nil {
		t.Fatal(err)
	}
	exec := func(c *pgx.Conn, q string) {
		t.Helper()
		if _, e := c.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	exec(owner, `INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-0000-0000-000000000015','chunks','cowrie');
 INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-0000-0000-000000000015','10000000-0000-0000-0000-000000000015','/chunks',15,15);
 INSERT INTO cheesetrap.events(event_id,sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,source_ip,destination_ip,destination_port,service,event_type,attributes,raw_hash)
 SELECT ('00000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid,'10000000-0000-0000-0000-000000000015','20000000-0000-0000-0000-000000000015',n,n,1,'cowrie','1.1.1.1','8.8.8.8',22,'ssh','login.failed','{}',repeat('a',64) FROM generate_series(1,130)n;
 UPDATE cheesetrap.processing_cursors SET ingested_seq=130;
 INSERT INTO cheesetrap.detection_completions(ingestion_seq,event_id,rule_set_version) SELECT ingestion_seq,event_id,'1' FROM cheesetrap.events;`)
	fixtureIDs := []string{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000130"}
	hash := func(ids []string) string {
		b, _ := json.Marshal(ids)
		h := sha256.Sum256(b)
		return hex.EncodeToString(h[:])
	}
	root := func(id, format string, count int) string {
		return `INSERT INTO cheesetrap.detection_results(detection_id,rule_id,rule_version,processing_event_id,processing_ingestion_seq,source_ip,window_start,window_end,evidence_hash,evidence_count,evidence_eligible,auto_approval_allowed,explanation,evidence_representation) VALUES('` + id + `','SSH-REPEAT','` + id + `','00000000-0000-0000-0000-000000000130',130,'1.1.1.1',now(),now(),'` + hash(fixtureIDs) + `',` + strconv.Itoa(count) + `,false,true,'{}','` + format + `')`
	}
	ids := `ARRAY['00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000130']::uuid[]`
	attach := func(id, items string) string {
		return `SELECT cheesetrap.store_detection_chunks('` + id + `',64,` + items + `)`
	}
	legacyID := "30000000-0000-0000-0000-000000000009"
	legacySQL := strings.Replace(root(legacyID, "legacy", 3), ",evidence_representation)", ")", 1)
	legacySQL = strings.TrimSuffix(legacySQL, ",'legacy')") + ")"
	exec(worker, legacySQL)
	exec(worker, `INSERT INTO cheesetrap.detection_evidence SELECT '`+legacyID+`',unnest(`+ids+`)`)
	var before, after string
	snapshot := `SELECT jsonb_build_object('root',to_jsonb(d)-'evidence_representation'-'evidence_state','ids',(SELECT jsonb_agg(event_id ORDER BY event_id) FROM cheesetrap.detection_evidence WHERE detection_id=d.detection_id))::text FROM cheesetrap.detection_results d WHERE detection_id=$1`
	if err = owner.QueryRow(ctx, snapshot, legacyID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	checkPartialLegacyUpgrade := seedPartialLegacyRetention(t, owner, worker)
	if _, err = provider.UpTo(ctx, 19); err != nil {
		t.Fatal(err)
	}
	if err = owner.QueryRow(ctx, snapshot, legacyID).Scan(&after); err != nil || before != after {
		t.Fatalf("legacy changed during migration: %v", err)
	}
	t.Run("partial_legacy_retention_upgrade", checkPartialLegacyUpgrade)
	exec(worker, attach(legacyID, ids))
	t.Run("legacy_cleanup_compatibility", func(t *testing.T) {
		if _, e := worker.Exec(ctx, "SELECT * FROM cheesetrap.retention_cleanup(now(),1)"); e != nil {
			t.Fatal(e)
		}
	})

	exec(owner, `CREATE SEQUENCE cheesetrap.test_chunk_ref_statements;
 CREATE FUNCTION cheesetrap.test_chunk_ref_statement() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('cheesetrap.test_chunk_ref_statements'); RETURN NULL; END $$;
 CREATE TRIGGER test_chunk_ref_statement AFTER INSERT ON cheesetrap.detection_evidence_chunks FOR EACH STATEMENT EXECUTE FUNCTION cheesetrap.test_chunk_ref_statement()`)
	t.Cleanup(func() {
		owner.Exec(ctx, `DROP TRIGGER test_chunk_ref_statement ON cheesetrap.detection_evidence_chunks; DROP FUNCTION cheesetrap.test_chunk_ref_statement(); DROP SEQUENCE cheesetrap.test_chunk_ref_statements`)
	})
	a, b := "30000000-0000-0000-0000-000000000001", "30000000-0000-0000-0000-000000000002"
	for _, id := range []string{a, b} {
		exec(worker, "BEGIN")
		exec(worker, root(id, "chunks-v1", 3))
		exec(worker, attach(id, ids))
		exec(worker, "COMMIT")
	}
	t.Run("schema19_to30_preserves_committed_mixed_evidence", func(t *testing.T) {
		fingerprint := func() string {
			t.Helper()
			var out strings.Builder
			for _, table := range []string{"events", "detection_completions", "detection_results", "detection_evidence", "evidence_chunks", "evidence_chunk_members", "detection_evidence_chunks", "reports", "report_revisions", "report_evidence"} {
				var digest string
				if err := owner.QueryRow(ctx, "SELECT md5(coalesce(string_agg(row::text, ',' ORDER BY row::text),'')) FROM (SELECT to_jsonb(t)-'evidence_hash_scheme' AS row FROM cheesetrap."+table+" t) x").Scan(&digest); err != nil {
					t.Fatal(err)
				}
				out.WriteString(table + ":" + digest + ";")
			}
			return out.String()
		}
		for _, target := range []int{20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30} {
			t.Run(fmt.Sprintf("schema%d_to%d", target-1, target), func(t *testing.T) {
				var version int
				if err := owner.QueryRow(ctx, `SELECT max(version_id) FROM cheesetrap.goose_db_version WHERE is_applied`).Scan(&version); err != nil || version != target-1 {
					t.Fatalf("upgrade must start at%d: %d %v", target-1, version, err)
				}

				if target == 26 {
					// A legacy snapshot may still have active mixed roots or only a copied
					// event whose old root has already been retired. Backfill both cases.
					exec(owner, `INSERT INTO cheesetrap.report_windows(window_id,start_at,end_at,settings_version) VALUES('40000000-0000-0000-0000-000000000026',now()-interval '2 hours',now()-interval '1 hour',1);
      INSERT INTO cheesetrap.reports(report_id,window_id,source_ip) VALUES('50000000-0000-0000-0000-000000000026','40000000-0000-0000-0000-000000000026','1.1.1.1');
      INSERT INTO cheesetrap.report_evidence(event_id,report_id,snapshot) VALUES('00000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000026','{}'),('00000000-0000-0000-0000-000000000003','50000000-0000-0000-0000-000000000026','{}');`)
				}
				before := fingerprint()
				// The query-only upgrade must preserve history, list epochs,
				// ownership/grants and every classifier attribute except its body.
				const queryState = `SELECT jsonb_build_object('history',(SELECT jsonb_agg(to_jsonb(h) ORDER BY event_id) FROM cheesetrap.event_evidence_history h),'list_state',(SELECT jsonb_agg(to_jsonb(s) ORDER BY singleton) FROM cheesetrap.event_list_state s),'classifier',(SELECT to_jsonb(p)-'prosrc' FROM pg_proc p WHERE oid='cheesetrap.event_detection_result(uuid,bigint,bigint)'::regprocedure))::text`
				var queryBefore string
				if target == 27 {
					if err := owner.QueryRow(ctx, queryState).Scan(&queryBefore); err != nil {
						t.Fatal(err)
					}
				}
				const security = `SELECT jsonb_agg(jsonb_build_object('name',proname,'security_definer',prosecdef,'config',proconfig,'acl',proacl,'owner',proowner,'args',proargnames,'types',proargtypes,'returns',prorettype) ORDER BY proname)::text FROM pg_proc WHERE oid IN ('cheesetrap.retention_cleanup(timestamptz,integer)'::regprocedure,'cheesetrap.validate_evidence_root()'::regprocedure)`
				securityQuery := security
				var configBefore []string
				if target == 24 {
					// Schema24 may add only the local JIT setting; both function
					// bodies and every other configuration/privilege stay exact.
					securityQuery = strings.Replace(security, "'name',proname", "'body',prosrc,'name',proname", 1)
					if err := owner.QueryRow(ctx, `SELECT proconfig FROM pg_proc WHERE oid='cheesetrap.validate_evidence_root()'::regprocedure`).Scan(&configBefore); err != nil {
						t.Fatal(err)
					}
				}
				var securityBefore, securityAfter string
				if err := owner.QueryRow(ctx, securityQuery).Scan(&securityBefore); err != nil {
					t.Fatal(err)
				}
				if target < 30 {
					if _, err := provider.UpTo(ctx, int64(target)); err != nil {
						t.Fatal(err)
					}
				} else if err := store.Migrate(ctx, os.Getenv("CHEESETRAP_TEST_CHUNKS_MIGRATION_URL")); err != nil {
					t.Fatal(err)
				}
				expectedVersion := target
				if target == 30 {
					expectedVersion = 31
				}
				if err := owner.QueryRow(ctx, `SELECT max(version_id) FROM cheesetrap.goose_db_version WHERE is_applied`).Scan(&version); err != nil || version != expectedVersion {
					t.Fatalf("upgrade must finish at%d: %d %v", expectedVersion, version, err)
				}
				if target == 27 {
					var queryAfter string
					if err := owner.QueryRow(ctx, queryState).Scan(&queryAfter); err != nil || queryAfter != queryBefore {
						t.Fatalf("query-only upgrade changed evidence history, snapshot state or classifier metadata: %v", err)
					}
				}
				if after := fingerprint(); before != after {
					t.Fatalf("schema%d changed committed mixed evidence or report copies", target)
				}

				if target == 26 {
					var markers []int64
					if err := owner.QueryRow(ctx, `SELECT array_agg(first_detection_seq ORDER BY event_id) FROM cheesetrap.event_evidence_history WHERE event_id IN ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003')`).Scan(&markers); err != nil || !slices.Equal(markers, []int64{130, 0}) {
						t.Fatalf("legacy copy backfill: %v %v", markers, err)
					}
				}
				if target == 24 {
					var configAfter []string
					if err := owner.QueryRow(ctx, `SELECT proconfig FROM pg_proc WHERE oid='cheesetrap.validate_evidence_root()'::regprocedure`).Scan(&configAfter); err != nil || !slices.Equal(configAfter, append(configBefore, "jit=off")) {
						t.Fatalf("schema24 must add only root-local jit=off: %v -> %v (%v)", configBefore, configAfter, err)
					}
					securityQuery = strings.Replace(securityQuery, "'config',proconfig", "'config',CASE WHEN proname='validate_evidence_root' THEN array_remove(proconfig,'jit=off') ELSE proconfig END", 1)
				}
				if target == 28 {
					securityQuery = strings.Replace(securityQuery, "'config',proconfig", "'config',CASE WHEN proname='validate_evidence_root' THEN array_remove(proconfig,'work_mem=4MB') ELSE proconfig END", 1)
					var changed int
					if err := owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.detection_results WHERE evidence_hash_scheme<>'sha256-json-v1'`).Scan(&changed); err != nil || changed != 0 {
						t.Fatal("historical hash scheme changed", changed, err)
					}
				}
				if err := owner.QueryRow(ctx, securityQuery).Scan(&securityAfter); err != nil || securityBefore != securityAfter {
					t.Fatalf("schema%d changed cleanup/root-proof grants, owner, signature, or settings: %s -> %s (%v)", target, securityBefore, securityAfter, err)
				}
			})
		}
		var index bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE schemaname='cheesetrap' AND indexname='detection_results_processing_event_idx' AND indexdef LIKE '%(processing_event_id)%')`).Scan(&index); err != nil || !index {
			t.Fatal("processing-event FK/protection index missing", err)
		}
	})
	var statements int
	if err := owner.QueryRow(ctx, `SELECT last_value FROM cheesetrap.test_chunk_ref_statements`).Scan(&statements); err != nil || statements != 2 {
		t.Fatalf("two multi-bucket roots require two reference statements, got %d: %v", statements, err)
	}
	var n int
	if e := owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.evidence_chunks").Scan(&n); e != nil || n != 2 {
		t.Fatalf("equal subsets not shared: %d %v", n, e)
	}
	t.Run("root_validation_jit_scope", func(t *testing.T) {
		exec(owner, "BEGIN")
		defer owner.Exec(ctx, "ROLLBACK")
		// Observe the real deferred validator through its hash helper without
		// changing the hash calculation. All observer DDL is rolled back.
		exec(owner, `SET LOCAL jit=on;
 CREATE TABLE cheesetrap.test_root_jit_observation(jit text);
 CREATE OR REPLACE FUNCTION cheesetrap.evidence_set_hash(ids uuid[]) RETURNS text
 LANGUAGE plpgsql VOLATILE STRICT SET search_path=pg_catalog,cheesetrap AS $$
 BEGIN
  INSERT INTO cheesetrap.test_root_jit_observation VALUES(current_setting('jit'));
  RETURN encode(sha256(convert_to(array_to_json(ids)::text,'UTF8')),'hex');
 END $$`)
		id := "30000000-0000-0000-0000-000000000090"
		exec(owner, root(id, "chunks-v1", 3))
		exec(owner, `INSERT INTO cheesetrap.detection_evidence_chunks SELECT '`+id+`',bucket_no,chunk_id FROM cheesetrap.evidence_chunks WHERE bucket_width=64`)
		exec(owner, `SET CONSTRAINTS cheesetrap.complete_evidence_root IMMEDIATE`)
		var observed []string
		if err := owner.QueryRow(ctx, `SELECT array_agg(jit) FROM cheesetrap.test_root_jit_observation`).Scan(&observed); err != nil || len(observed) != 1 || observed[0] != "off" {
			t.Errorf("root validator must execute with local jit=off: observed=%v err=%v", observed, err)
		}
		var caller string
		if err := owner.QueryRow(ctx, `SHOW jit`).Scan(&caller); err != nil || caller != "on" {
			t.Fatalf("root validator changed caller jit: %s %v", caller, err)
		}
	})
	exec(worker, attach(a, ids)) // uncertain commit retry
	reject := func(name, state, q string, c *pgx.Conn) {
		t.Run(name, func(t *testing.T) {
			_, e := c.Exec(ctx, q)
			if sqlState(e) != state {
				t.Fatalf("want %s got %s (%v)", state, sqlState(e), e)
			}
		})
	}
	reject("duplicate", "23514", attach(a, `ARRAY['00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000130']::uuid[]`), worker)
	reject("missing_event", "23503", attach(a, `ARRAY['00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','ffffffff-ffff-ffff-ffff-ffffffffffff']::uuid[]`), worker)
	reject("changed_retry", "23514", attach(a, `ARRAY['00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000130']::uuid[]`), worker)
	// Bypass only the immediate reference guards as the fixture owner to prove
	// the real deferred root constraint independently rejects malformed proofs.
	// A failed COMMIT rolls back the fixture and the transactional trigger DDL.
	for i, shape := range []string{"count", "hash", "duplicate", "width"} {
		t.Run("deferred_root_"+shape, func(t *testing.T) {
			exec(owner, "BEGIN")
			defer owner.Exec(ctx, "ROLLBACK")
			exec(owner, `ALTER TABLE cheesetrap.detection_evidence_chunks DISABLE TRIGGER guard_chunk_refs; ALTER TABLE cheesetrap.detection_evidence_chunks DISABLE TRIGGER guard_chunk_attachments`)
			id := fmt.Sprintf("30000000-0000-0000-0000-%012d", 80+i)
			count := 3
			if shape == "count" || shape == "duplicate" {
				count = 4
			}
			q := root(id, "chunks-v1", count)
			if shape == "hash" {
				q = strings.Replace(q, hash(fixtureIDs), strings.Repeat("f", 64), 1)
			}
			if shape == "duplicate" {
				q = strings.Replace(q, hash(fixtureIDs), hash([]string{fixtureIDs[0], fixtureIDs[0], fixtureIDs[1], fixtureIDs[1]}), 1)
			}
			exec(owner, q)
			switch shape {
			case "duplicate":
				exec(owner, `INSERT INTO cheesetrap.detection_evidence_chunks SELECT '`+id+`',b,chunk_id FROM cheesetrap.evidence_chunks CROSS JOIN generate_series(0,1)b WHERE bucket_width=64 AND bucket_no=0`)
			case "width":
				exec(owner, `INSERT INTO cheesetrap.evidence_chunks(chunk_id,bucket_width,bucket_no,content_hash,member_count) VALUES('40000000-0000-0000-0000-000000000080',128,1,cheesetrap.chunk_content_hash(128,1,ARRAY['00000000-0000-0000-0000-000000000130']::uuid[]),1); INSERT INTO cheesetrap.evidence_chunk_members VALUES('40000000-0000-0000-0000-000000000080','00000000-0000-0000-0000-000000000130')`)
				exec(owner, `INSERT INTO cheesetrap.detection_evidence_chunks SELECT '`+id+`',bucket_no,chunk_id FROM cheesetrap.evidence_chunks WHERE (bucket_width=64 AND bucket_no=0) OR chunk_id='40000000-0000-0000-0000-000000000080'`)
			default:
				exec(owner, `INSERT INTO cheesetrap.detection_evidence_chunks SELECT '`+id+`',bucket_no,chunk_id FROM cheesetrap.evidence_chunks WHERE bucket_width=64`)
			}
			_, e := owner.Exec(ctx, "COMMIT")
			if sqlState(e) != "23514" || !strings.Contains(e.Error(), "incomplete_evidence_root") {
				t.Fatalf("deferred %s proof accepted or wrong rejection: %v", shape, e)
			}
			var remaining int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.detection_results WHERE detection_id=$1`, id).Scan(&remaining); err != nil || remaining != 0 {
				t.Fatalf("invalid proof did not roll back: %d %v", remaining, err)
			}
		})
	}
	reject("incomplete", "23514", root("30000000-0000-0000-0000-000000000003", "chunks-v1", 3), worker)
	reject("mixed", "23514", `INSERT INTO cheesetrap.detection_evidence VALUES('`+a+`','00000000-0000-0000-0000-000000000001')`, worker)
	retiringSQL := strings.Replace(root("30000000-0000-0000-0000-000000000004", "chunks-v1", 3), "evidence_representation)", "evidence_representation,evidence_state)", 1)
	reject("retiring_forgery", "23514", strings.TrimSuffix(retiringSQL, ")")+",'retiring')", worker)

	for _, role := range []string{"API", "COLLECTOR", "WORKER"} {
		c := connect(role)
		for _, table := range []string{"evidence_chunks", "evidence_chunk_members", "detection_evidence_chunks"} {
			for _, q := range []string{"INSERT INTO cheesetrap." + table + " DEFAULT VALUES", "UPDATE cheesetrap." + table + " SET chunk_id=chunk_id", "DELETE FROM cheesetrap." + table, "TRUNCATE cheesetrap." + table} {
				reject(role+q, "42501", q, c)
			}
		}
		if role != "WORKER" {
			reject(role+"execute", "42501", attach(a, ids), c)
		}
	}
	reject("wrong_bucket", "23514", `INSERT INTO cheesetrap.evidence_chunk_members SELECT chunk_id,'00000000-0000-0000-0000-000000000003' FROM cheesetrap.evidence_chunks WHERE bucket_no=2`, owner)
	reject("completed_chunk", "23514", `INSERT INTO cheesetrap.evidence_chunk_members SELECT chunk_id,'00000000-0000-0000-0000-000000000003' FROM cheesetrap.evidence_chunks WHERE bucket_no=0`, owner)
	t.Run("collision_contents", func(t *testing.T) {
		exec(owner, "BEGIN")
		defer owner.Exec(ctx, "ROLLBACK")
		id := "30000000-0000-0000-0000-000000000010"
		exec(owner, root(id, "chunks-v1", 3))
		exec(owner, `INSERT INTO cheesetrap.evidence_chunks(chunk_id,bucket_width,bucket_no,content_hash,member_count) VALUES('40000000-0000-0000-0000-000000000001',128,0,cheesetrap.chunk_content_hash(128,0,ARRAY['00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002']::uuid[]),1)`)
		exec(owner, `INSERT INTO cheesetrap.evidence_chunk_members VALUES('40000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003')`)
		_, e := owner.Exec(ctx, strings.Replace(attach(id, ids), ",64,", ",128,", 1))
		if sqlState(e) != "23514" || !strings.Contains(e.Error(), "chunk_content_collision") {
			t.Fatalf("collision not rejected: %v", e)
		}
	})
	t.Run("member_fk", func(t *testing.T) {
		exec(owner, "BEGIN")
		defer owner.Exec(ctx, "ROLLBACK")
		exec(owner, `INSERT INTO cheesetrap.evidence_chunks(chunk_id,bucket_width,bucket_no,content_hash,member_count) VALUES('40000000-0000-0000-0000-000000000002',128,0,repeat('b',64),1)`)
		_, e := owner.Exec(ctx, `INSERT INTO cheesetrap.evidence_chunk_members VALUES('40000000-0000-0000-0000-000000000002','ffffffff-ffff-ffff-ffff-ffffffffffff')`)
		if sqlState(e) != "23503" {
			t.Fatalf("missing FK: %v", e)
		}
	})
	t.Run("duplicate_member", func(t *testing.T) {
		exec(owner, "BEGIN")
		defer owner.Exec(ctx, "ROLLBACK")
		exec(owner, `INSERT INTO cheesetrap.evidence_chunks(chunk_id,bucket_width,bucket_no,content_hash,member_count) VALUES('40000000-0000-0000-0000-000000000002',128,0,repeat('b',64),2)`)
		exec(owner, `INSERT INTO cheesetrap.evidence_chunk_members VALUES('40000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001')`)
		_, e := owner.Exec(ctx, `INSERT INTO cheesetrap.evidence_chunk_members VALUES('40000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001')`)
		if sqlState(e) != "23505" {
			t.Fatalf("duplicate member accepted: %v", e)
		}
	})

	t.Run("multirow_attachment_bounds", func(t *testing.T) {
		exec(owner, "BEGIN")
		defer owner.Exec(ctx, "ROLLBACK")
		id := "30000000-0000-0000-0000-000000000018"
		exec(owner, root(id, "chunks-v1", 2))
		_, e := owner.Exec(ctx, `INSERT INTO cheesetrap.detection_evidence_chunks SELECT '`+id+`'::uuid,bucket_no,chunk_id FROM cheesetrap.detection_evidence_chunks WHERE detection_id='`+a+`'`)
		if sqlState(e) != "23514" || !strings.Contains(e.Error(), "invalid_chunk_attachment") {
			t.Fatalf("multirow overfull attachment accepted: %v", e)
		}
	})
	t.Run("multiroot_attachment_failure_is_atomic", func(t *testing.T) {
		exec(owner, "BEGIN")
		defer owner.Exec(ctx, "ROLLBACK")
		valid, invalid := "30000000-0000-0000-0000-000000000018", "30000000-0000-0000-0000-000000000019"
		exec(owner, root(valid, "chunks-v1", 3))
		exec(owner, root(invalid, "chunks-v1", 2))
		exec(owner, "SAVEPOINT attachment_statement")
		_, e := owner.Exec(ctx, `INSERT INTO cheesetrap.detection_evidence_chunks
 SELECT target.id,c.bucket_no,c.chunk_id
 FROM (VALUES ('`+valid+`'::uuid),('`+invalid+`'::uuid)) target(id)
 CROSS JOIN cheesetrap.detection_evidence_chunks c WHERE c.detection_id='`+a+`'
 ORDER BY target.id,c.bucket_no`)
		if sqlState(e) != "23514" || !strings.Contains(e.Error(), "invalid_chunk_attachment") {
			t.Fatalf("multi-root statement with an overfull root accepted: %v", e)
		}
		exec(owner, "ROLLBACK TO SAVEPOINT attachment_statement")
		var remaining int
		if e := owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.detection_evidence_chunks WHERE detection_id IN ($1,$2)`, valid, invalid).Scan(&remaining); e != nil || remaining != 0 {
			t.Fatalf("failed multi-root statement retained references: %d, %v", remaining, e)
		}
		// The first root is independently valid; its rows disappeared because
		// the entire mixed statement failed, not because its proof was invalid.
		exec(owner, `INSERT INTO cheesetrap.detection_evidence_chunks SELECT '`+valid+`'::uuid,bucket_no,chunk_id FROM cheesetrap.detection_evidence_chunks WHERE detection_id='`+a+`'`)
		if e := owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.detection_evidence_chunks WHERE detection_id=$1`, valid).Scan(&remaining); e != nil || remaining != 2 {
			t.Fatalf("independently valid root did not attach both buckets: %d, %v", remaining, e)
		}
	})
	t.Run("multirow_attachment_widths", func(t *testing.T) {
		exec(owner, "BEGIN")
		defer owner.Exec(ctx, "ROLLBACK")
		id := "30000000-0000-0000-0000-000000000018"
		exec(owner, root(id, "chunks-v1", 3))
		exec(owner, `INSERT INTO cheesetrap.evidence_chunks(chunk_id,bucket_width,bucket_no,content_hash,member_count) VALUES('40000000-0000-0000-0000-000000000018',128,1,cheesetrap.chunk_content_hash(128,1,ARRAY['00000000-0000-0000-0000-000000000130']::uuid[]),1);
 INSERT INTO cheesetrap.evidence_chunk_members VALUES('40000000-0000-0000-0000-000000000018','00000000-0000-0000-0000-000000000130')`)
		_, e := owner.Exec(ctx, `INSERT INTO cheesetrap.detection_evidence_chunks SELECT '`+id+`'::uuid,bucket_no,chunk_id FROM cheesetrap.detection_evidence_chunks WHERE detection_id='`+a+`' AND bucket_no=0 UNION ALL SELECT '`+id+`'::uuid,1,'40000000-0000-0000-0000-000000000018'::uuid`)
		if sqlState(e) != "23514" || !strings.Contains(e.Error(), "invalid_chunk_attachment") {
			t.Fatalf("mixed-width multirow attachment accepted: %v", e)
		}
	})
	t.Run("completed_root_append_with_conflict", func(t *testing.T) {
		exec(owner, "BEGIN")
		defer owner.Exec(ctx, "ROLLBACK")
		// Empty transition tables from retries must pass. A genuinely new row
		// in a later statement must still count all previously attached rows.
		exec(owner, `INSERT INTO cheesetrap.detection_evidence_chunks SELECT * FROM cheesetrap.detection_evidence_chunks WHERE detection_id='`+a+`' ON CONFLICT DO NOTHING`)
		exec(owner, `INSERT INTO cheesetrap.evidence_chunks(chunk_id,bucket_width,bucket_no,content_hash,member_count) VALUES('40000000-0000-0000-0000-000000000018',64,1,cheesetrap.chunk_content_hash(64,1,ARRAY['00000000-0000-0000-0000-000000000065']::uuid[]),1);
 INSERT INTO cheesetrap.evidence_chunk_members VALUES('40000000-0000-0000-0000-000000000018','00000000-0000-0000-0000-000000000065')`)
		_, e := owner.Exec(ctx, `INSERT INTO cheesetrap.detection_evidence_chunks VALUES('`+a+`',1,'40000000-0000-0000-0000-000000000018') ON CONFLICT DO NOTHING`)
		if sqlState(e) != "23514" || !strings.Contains(e.Error(), "invalid_chunk_attachment") {
			t.Fatalf("append to complete root accepted: %v", e)
		}
	})

	t.Run("hash_mismatch", func(t *testing.T) {
		exec(worker, "BEGIN")
		defer worker.Exec(ctx, "ROLLBACK")
		id := "30000000-0000-0000-0000-000000000005"
		exec(worker, strings.Replace(root(id, "chunks-v1", 3), hash(fixtureIDs), strings.Repeat("b", 64), 1))
		_, err := worker.Exec(ctx, attach(id, ids))
		if sqlState(err) != "23514" {
			t.Fatalf("hash mismatch accepted: %v", err)
		}
	})
	t.Run("distinct_subsets", func(t *testing.T) {
		id := "30000000-0000-0000-0000-000000000006"
		other := []string{fixtureIDs[0], "00000000-0000-0000-0000-000000000003", fixtureIDs[2]}
		exec(worker, "BEGIN")
		exec(worker, strings.Replace(root(id, "chunks-v1", 3), hash(fixtureIDs), hash(other), 1))
		exec(worker, attach(id, strings.Replace(ids, fixtureIDs[1], other[1], 1)))
		exec(worker, "COMMIT")
		if e := owner.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.evidence_chunks").Scan(&n); e != nil || n != 3 {
			t.Fatalf("distinct subsets not isolated: %d %v", n, e)
		}
	})

	t.Run("completion_failure_rolls_back", func(t *testing.T) {
		counts := func() string {
			var v string
			e := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM cheesetrap.detection_results),(SELECT count(*) FROM cheesetrap.evidence_chunks),(SELECT count(*) FROM cheesetrap.evidence_chunk_members),(SELECT count(*) FROM cheesetrap.detection_evidence_chunks))::text`).Scan(&v)
			if e != nil {
				t.Fatal(e)
			}
			return v
		}
		before := counts()
		id := "30000000-0000-0000-0000-000000000007"
		other := []string{fixtureIDs[0], "00000000-0000-0000-0000-000000000004", fixtureIDs[2]}
		exec(worker, "BEGIN")
		badRoot := strings.Replace(root(id, "chunks-v1", 3), "',130,'1.1.1.1'", "',129,'1.1.1.1'", 1)
		exec(worker, strings.Replace(badRoot, hash(fixtureIDs), hash(other), 1))
		exec(worker, attach(id, strings.Replace(ids, fixtureIDs[1], other[1], 1)))
		var inside int
		if e := worker.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.evidence_chunks").Scan(&inside); e != nil || inside != 4 {
			t.Fatalf("fixture did not create novel chunk: %d %v", inside, e)
		}
		_, e := worker.Exec(ctx, "COMMIT")
		if sqlState(e) != "23503" {
			t.Fatalf("completion failure: %v", e)
		}
		if after := counts(); after != before {
			t.Fatalf("failed completion leaked data: %s -> %s", before, after)
		}
	})
	t.Run("retired_result_retry", func(t *testing.T) {
		exec(owner, "BEGIN")
		defer owner.Exec(ctx, "ROLLBACK")
		// Migration-owner fixture models future cleanup; runtime cannot disable guards.
		exec(owner, "ALTER TABLE cheesetrap.detection_results DISABLE TRIGGER guard_evidence_root")
		exec(owner, "UPDATE cheesetrap.detection_results SET evidence_state='retiring' WHERE detection_id='"+a+"'")
		exec(owner, "ALTER TABLE cheesetrap.detection_results ENABLE TRIGGER guard_evidence_root")
		_, e := owner.Exec(ctx, attach(a, ids))
		if sqlState(e) != "23514" || !strings.Contains(e.Error(), "retired_result") {
			t.Fatalf("retired retry accepted: %v", e)
		}
	})
	t.Run("unattached_wrong_bucket", func(t *testing.T) {
		exec(owner, "BEGIN")
		defer owner.Exec(ctx, "ROLLBACK")
		exec(owner, `INSERT INTO cheesetrap.evidence_chunks(chunk_id,bucket_width,bucket_no,content_hash,member_count) VALUES('40000000-0000-0000-0000-000000000002',128,0,repeat('b',64),1)`)
		_, e := owner.Exec(ctx, `INSERT INTO cheesetrap.evidence_chunk_members VALUES('40000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000130')`)
		if sqlState(e) != "23514" {
			t.Fatalf("wrong bucket accepted: %v", e)
		}
	})

	t.Run("legacy_retry", func(t *testing.T) {
		id := "30000000-0000-0000-0000-000000000008"
		exec(worker, root(id, "legacy", 3))
		exec(worker, `INSERT INTO cheesetrap.detection_evidence SELECT '`+id+`',unnest(`+ids+`)`)
		exec(worker, attach(id, ids))
	})
	t.Run("cursor_first", func(t *testing.T) {
		exec(owner, "BEGIN")
		defer owner.Exec(ctx, "ROLLBACK")
		exec(owner, "SELECT 1 FROM cheesetrap.processing_cursors FOR UPDATE")
		timed, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		defer cancel()
		if _, e := worker.Exec(timed, attach(a, ids)); e == nil {
			t.Fatal("writer bypassed cursor lock")
		}
		// Cancellation may close a pgx connection; use a fresh authenticated worker.
		worker = connect("WORKER")
	})

	exec(worker, `SELECT * FROM cheesetrap.retention_cleanup(now(),1)`)
}
