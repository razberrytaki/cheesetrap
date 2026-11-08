//go:build integration

package retention

import (
	"cheesetrap/internal/store"
	"context"
	"os"
	"testing"
	"time"
)

func TestRetentionPolicySQL(t *testing.T) {
	ctx := context.Background()
	p, e := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_POLICY_MIGRATION_URL"))
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	worker, e := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_POLICY_WORKER_URL"))
	if e != nil {
		t.Fatal(e)
	}
	defer worker.Close()
	var days int
	if e = p.QueryRow(ctx, `SELECT (cheesetrap.retention_policy()->>'event_days')::integer`).Scan(&days); e != nil || days != 30 {
		t.Fatal(days, e)
	}
	if _, e = p.Exec(ctx, `UPDATE cheesetrap.settings SET value=jsonb_set(value,'{retention}','{"raw_days":2,"raw_bytes":"33554432","event_days":1,"history_days":2,"job_days":1}') WHERE key='review_policy'`); e != nil {
		t.Fatal(e)
	}
	if e = p.QueryRow(ctx, `SELECT (cheesetrap.retention_policy()->>'event_days')::integer`).Scan(&days); e != nil || days != 1 {
		t.Fatal(days, e)
	}

	// Same two-day-old completed event survives a three-day policy, then becomes
	// eligible after shortening to one day. The raw event's meaning is unchanged.
	var sensor, generation, event string
	var seq int64
	if e = p.QueryRow(ctx, `INSERT INTO cheesetrap.sensors(name,engine) VALUES('policy-fixture','cowrie') RETURNING sensor_id::text`).Scan(&sensor); e != nil {
		t.Fatal(e)
	}
	if e = p.QueryRow(ctx, `INSERT INTO cheesetrap.file_generations(sensor_id,path,device,inode) VALUES($1,'/policy',1,1) RETURNING file_generation_id::text`, sensor).Scan(&generation); e != nil {
		t.Fatal(e)
	}
	if e = p.QueryRow(ctx, `UPDATE cheesetrap.processing_cursors SET ingested_seq=ingested_seq+1,detected_seq=ingested_seq+1,sealed_before=clock_timestamp() WHERE singleton RETURNING ingested_seq`).Scan(&seq); e != nil {
		t.Fatal(e)
	}
	if e = p.QueryRow(ctx, `INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,ingested_at,service,event_type,raw_hash) VALUES($1,$2,0,$3,1,'cowrie',clock_timestamp()-interval '2 days','ssh','test',repeat('a',64)) RETURNING event_id::text`, sensor, generation, seq).Scan(&event); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `UPDATE cheesetrap.settings SET value=jsonb_set(value,'{retention,event_days}','3') WHERE key='review_policy'`); e != nil {
		t.Fatal(e)
	}
	if _, e = worker.Exec(ctx, `SELECT * FROM cheesetrap.retention_cleanup($1,100)`, time.Now()); e != nil {
		t.Fatal(e)
	}
	var exists bool
	if e = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap.events WHERE event_id=$1)`, event).Scan(&exists); e != nil || !exists {
		t.Fatal("longer policy removed event", e)
	}
	if _, e = p.Exec(ctx, `UPDATE cheesetrap.settings SET value=jsonb_set(value,'{retention,event_days}','1') WHERE key='review_policy'`); e != nil {
		t.Fatal(e)
	}
	if _, e = worker.Exec(ctx, `SELECT * FROM cheesetrap.retention_cleanup($1,100)`, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap.events WHERE event_id=$1)`, event).Scan(&exists); e != nil || exists {
		t.Fatal("shorter policy retained event", e)
	}
	// Dynamic history keeps immutable closed-unconfirmed minimum promises and
	// never makes held/unknown reports eligible, even with a one-day cutoff.
	var window, admin string
	if e = p.QueryRow(ctx, `INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version) VALUES(clock_timestamp()-interval '10 days',clock_timestamp()-interval '9 days',1) RETURNING window_id::text`).Scan(&window); e != nil {
		t.Fatal(e)
	}
	if e = p.QueryRow(ctx, `INSERT INTO cheesetrap.admins(username,password_hash) VALUES('policy-admin','fixture') RETURNING admin_id::text`).Scan(&admin); e != nil {
		t.Fatal(e)
	}
	ids := map[string]string{}
	for i, state := range []string{"sent", "held", "unknown", "closed_unconfirmed"} {
		tx, e := p.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		var report, revision string
		if e = tx.QueryRow(ctx, `SELECT gen_random_uuid()::text,gen_random_uuid()::text`).Scan(&report, &revision); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cheesetrap.reports(report_id,window_id,source_ip,version,current_revision_id,state,last_changed_at,delivery_uncertain) VALUES($1,$2,('8.8.4.'||$3::integer::text)::inet,1,$4,$5,clock_timestamp()-interval '3 days',$6)`, report, window, i+1, revision, state, state == "unknown" || state == "closed_unconfirmed"); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cheesetrap.report_revisions(revision_id,report_id,version,snapshot,subject,body,recipient,reply_to,hold_reasons,state,auto_approval_allowed,body_edited,content_digest) VALUES($1,$2,1,'{}','subject','body','abuse@example.org','ops@example.org','{}','needs_review',false,false,repeat('a',64))`, revision, report); e != nil {
			t.Fatal(e)
		}
		if state == "closed_unconfirmed" {
			if _, e = tx.Exec(ctx, `INSERT INTO cheesetrap.delivery_closures(report_id,admin_id,reason,closed_at,retention_until) VALUES($1,$2,'operator',statement_timestamp()-interval '3 days',statement_timestamp()+interval '177 days')`, report, admin); e != nil {
				t.Fatal(e)
			}
		}
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		ids[state] = report
	}
	for n := 0; n < 20; n++ {
		if _, e = worker.Exec(ctx, `SELECT * FROM cheesetrap.retention_cleanup($1,100)`, time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	for state, id := range ids {
		if e = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap.reports WHERE report_id=$1)`, id).Scan(&exists); e != nil || exists != (state != "sent") {
			t.Fatal("history protection", state, exists, e)
		}
	}
	if _, e = p.Exec(ctx, `INSERT INTO cheesetrap_river.river_job(kind,args,queue,state,finalized_at) VALUES('policy-old','{}','retention','completed',clock_timestamp()-interval '2 days'),('policy-young','{}','retention','completed',clock_timestamp()-interval '12 hours')`); e != nil {
		t.Fatal(e)
	}
	if _, e = worker.Exec(ctx, `SELECT * FROM cheesetrap.retention_cleanup($1,100)`, time.Now()); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = p.QueryRow(ctx, `SELECT count(*) FROM cheesetrap_river.river_job WHERE kind='policy-old'`).Scan(&count); e != nil || count != 0 {
		t.Fatal("custom job cutoff", count, e)
	}
	if e = p.QueryRow(ctx, `SELECT count(*) FROM cheesetrap_river.river_job WHERE kind='policy-young'`).Scan(&count); e != nil || count != 1 {
		t.Fatal("young job", count, e)
	}
	if _, e = p.Exec(ctx, `UPDATE cheesetrap.settings SET value=jsonb_set(value,'{retention}','null') WHERE key='review_policy'`); e != nil {
		t.Fatal(e)
	}
	if _, e = worker.Exec(ctx, `SELECT * FROM cheesetrap.retention_cleanup($1,100)`, time.Now()); e == nil {
		t.Fatal("invalid stored policy permitted cleanup")
	}
}
