//go:build integration

package detection

import (
	"cheesetrap/internal/store"
	"context"
	"os"
	"testing"
)

func TestRuleConfigBoundary(t *testing.T) {
	ctx := context.Background()
	owner, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_RULECONFIG_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	worker, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_RULECONFIG_WORKER_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	exec := func(sql string) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES('10000000-0000-4000-8000-000000000505','rule-config','cowrie');
 INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES('20000000-0000-4000-8000-000000000505','10000000-0000-4000-8000-000000000505','/fixture',1,1);
 INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,observed_at,source_ip,destination_ip,destination_port,service,event_type,attributes,raw_hash)
 SELECT '10000000-0000-4000-8000-000000000505','20000000-0000-4000-8000-000000000505',n,n,1,'cowrie',clock_timestamp(),'1.1.1.1','8.8.8.8',22,'ssh',CASE WHEN n=4 THEN 'cowrie.session.connect' ELSE 'cowrie.login.failed' END,'{}',repeat('a',64) FROM generate_series(1,4)n;
 UPDATE cheesetrap.processing_cursors SET ingested_seq=4;
 INSERT INTO cheesetrap.rule_config_versions(settings_version,effective_from_seq,config) VALUES(2,3,'{"ssh_repeat_threshold":2,"web_repeat_threshold":3,"web_distinct_path_threshold":2}');`)
	if _, err := ProcessBatch(ctx, worker, 100); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = owner.QueryRow(ctx, `SELECT count(*) FROM cheesetrap.detection_results WHERE processing_ingestion_seq=3 AND settings_version=2 AND explanation->>'threshold'='2'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("configured threshold did not change actual detection: count=%d err=%v", count, err)
	}
	var versions []int64
	if err = owner.QueryRow(ctx, `SELECT array_agg(settings_version ORDER BY ingestion_seq) FROM cheesetrap.detection_completions`).Scan(&versions); err != nil || len(versions) != 4 || versions[0] != 1 || versions[1] != 1 || versions[2] != 2 || versions[3] != 2 {
		t.Fatalf("ingested backlog was rerated: %v %v", versions, err)
	}
}
