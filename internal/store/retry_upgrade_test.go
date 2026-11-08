//go:build integration

package store_test

import (
	"cheesetrap/internal/reporting"
	"cheesetrap/internal/store"
	"cheesetrap/migrations"
	"context"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"os"
	"testing"
)

func TestRetryAndQuotaUpgrade(t *testing.T) {
	ctx := context.Background()
	p, e := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_RETRY_UPGRADE_MIGRATION_URL"))
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	provider, e := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(p), migrations.Files, goose.WithTableName("cheesetrap.goose_db_version"), goose.WithDisableGlobalRegistry(true))
	if e != nil {
		t.Fatal(e)
	}
	defer provider.Close()
	if _, e = provider.UpTo(ctx, 11); e != nil {
		t.Fatal(e)
	}
	type record struct {
		id, approval, state string
		n                   int
		transport           bool
	}
	var records []record
	for _, tc := range []struct {
		state     string
		n         int
		transport bool
	}{{"unknown", 1, false}, {"unknown", 0, false}, {"retry_wait", 1, false}, {"retry_wait", 3, false}, {"retry_wait", 1, true}} {
		id, rev, digest, actor, e := reporting.SeedLegacyRevision(ctx, p)
		if e != nil {
			t.Fatal(e)
		}
		var approval string
		if e = p.QueryRow(ctx, `INSERT INTO cheesetrap.approvals(report_id,revision_id,content_digest,admin_id,settings_version,schedule_version,approved_at,scheduled_at) VALUES($1,$2,$3,$4,1,1,clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour') RETURNING approval_id::text`, id, rev, digest, actor).Scan(&approval); e != nil {
			t.Fatal(e)
		}
		for _, state := range []string{"queued", "sending"} {
			if _, e = p.Exec(ctx, `UPDATE cheesetrap.reports SET state=$2,version=version+1 WHERE report_id=$1`, id, state); e != nil {
				t.Fatal(e)
			}
		}
		if tc.n > 0 {
			if _, e = p.Exec(ctx, `INSERT INTO cheesetrap.delivery_attempts(report_id,revision_id,approval_id,attempt_number,message_id,phase,result,classification,started_at,finished_at) SELECT $1,$2,$3,n,'test@invalid','response',$4,CASE WHEN $4='unknown' THEN 'smtp_acceptance_unknown' WHEN $6 THEN 'smtp_transport_failed' ELSE 'smtp_temporary_refusal' END,clock_timestamp()-interval '2 seconds',clock_timestamp()-interval '1 second' FROM generate_series(1,$5::integer) n`, id, rev, approval, tc.state, tc.n, tc.transport); e != nil {
				t.Fatal(e)
			}
		}
		if _, e = p.Exec(ctx, `UPDATE cheesetrap.reports SET state=$2,version=version+1 WHERE report_id=$1`, id, tc.state); e != nil {
			t.Fatal(e)
		}
		records = append(records, record{id, approval, tc.state, tc.n, tc.transport})
	}
	if _, e = provider.Up(ctx); e != nil {
		t.Fatal(e)
	}
	for _, r := range records {
		var state string
		var uncertain bool
		var count int
		if e = p.QueryRow(ctx, `SELECT state,delivery_uncertain,(SELECT count(*) FROM cheesetrap.delivery_attempts WHERE report_id=$1) FROM cheesetrap.reports WHERE report_id=$1`, r.id).Scan(&state, &uncertain, &count); e != nil {
			t.Fatal(e)
		}
		want := r.state
		if r.n >= 3 {
			want = "failed"
		}
		if state != want || uncertain != (r.state == "unknown") || count != r.n {
			t.Fatal(state, uncertain, count, r)
		}
		if r.state == "retry_wait" && r.n == 1 {
			var delay float64
			if e = p.QueryRow(ctx, `SELECT extract(epoch FROM due_at-(SELECT max(finished_at) FROM cheesetrap.delivery_attempts WHERE approval_id=$1)) FROM cheesetrap.delivery_schedule WHERE approval_id=$1`, r.approval).Scan(&delay); e != nil || delay < 300 || delay > 360 {
				t.Fatal(delay, e)
			}
		}
	}
	for _, role := range []string{"API", "WORKER", "COLLECTOR"} {
		db, e := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_RETRY_UPGRADE_"+role+"_URL"))
		if e != nil {
			t.Fatal(e)
		}
		defer db.Close()
		var closeInsert, closeUpdate, closeDelete, dueUpdate bool
		if e = db.QueryRow(ctx, `SELECT has_table_privilege(current_user,'cheesetrap.delivery_closures','INSERT'),has_table_privilege(current_user,'cheesetrap.delivery_closures','UPDATE'),has_table_privilege(current_user,'cheesetrap.delivery_closures','DELETE'),has_column_privilege(current_user,'cheesetrap.delivery_schedule','due_at','UPDATE')`).Scan(&closeInsert, &closeUpdate, &closeDelete, &dueUpdate); e != nil || closeInsert != (role == "API") || closeUpdate || closeDelete || dueUpdate != (role == "WORKER") {
			t.Fatal(role, closeInsert, closeUpdate, closeDelete, dueUpdate, e)
		}
	}
}
