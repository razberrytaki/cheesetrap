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

func TestSMTPUpgrade(t *testing.T) {
	ctx := context.Background()
	url := os.Getenv("CHEESETRAP_TEST_SMTP_UPGRADE_MIGRATION_URL")
	owner, e := store.NewPool(ctx, url)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	provider, e := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(owner), migrations.Files, goose.WithTableName("cheesetrap.goose_db_version"), goose.WithDisableGlobalRegistry(true))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = provider.UpTo(ctx, 10); e != nil {
		t.Fatal(e)
	}
	id, revision, digest, actor, e := reporting.SeedLegacyRevision(ctx, owner)
	if e != nil {
		t.Fatal(e)
	}
	var approval string
	if e = owner.QueryRow(ctx, `INSERT INTO cheesetrap.approvals(report_id,revision_id,content_digest,admin_id,settings_version,schedule_version,approved_at,scheduled_at) VALUES($1,$2,$3,$4,1,1,clock_timestamp(),clock_timestamp()+interval '1 day') RETURNING approval_id::text`, id, revision, digest, actor).Scan(&approval); e != nil {
		t.Fatal(e)
	}
	if _, e = owner.Exec(ctx, `UPDATE cheesetrap.reports SET state='queued',version=version+1 WHERE report_id=$1`, id); e != nil {
		t.Fatal(e)
	}
	if _, e = provider.Up(ctx); e != nil {
		t.Fatal(e)
	}
	defer provider.Close()
	var gotRevision, gotDigest, state string
	var version int
	if e = owner.QueryRow(ctx, `SELECT r.current_revision_id::text,v.content_digest,r.state,r.version FROM cheesetrap.reports r JOIN cheesetrap.report_revisions v ON v.revision_id=r.current_revision_id WHERE r.report_id=$1`, id).Scan(&gotRevision, &gotDigest, &state, &version); e != nil || gotRevision != revision || gotDigest != digest || state != "queued" || version != 2 {
		t.Fatal("upgrade mutated review history", e)
	}
	for _, role := range []string{"API", "WORKER", "COLLECTOR"} {
		p, e := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_SMTP_UPGRADE_"+role+"_URL"))
		if e != nil {
			t.Fatal(e)
		}
		defer p.Close()
		var read, insert, finish, identity, del bool
		e = p.QueryRow(ctx, `SELECT has_table_privilege(current_user,'cheesetrap.delivery_attempts','SELECT'),has_table_privilege(current_user,'cheesetrap.delivery_attempts','INSERT'),has_column_privilege(current_user,'cheesetrap.delivery_attempts','result','UPDATE'),has_column_privilege(current_user,'cheesetrap.delivery_attempts','revision_id','UPDATE'),has_table_privilege(current_user,'cheesetrap.delivery_attempts','DELETE')`).Scan(&read, &insert, &finish, &identity, &del)
		if e != nil || read != (role != "COLLECTOR") || insert != (role == "WORKER") || finish != (role == "WORKER") || identity || del {
			t.Fatal("delivery role privileges", role, e)
		}
	}
	if _, e = owner.Exec(ctx, `INSERT INTO cheesetrap.delivery_attempts(report_id,revision_id,approval_id,attempt_number,message_id,phase,result,classification) VALUES($1,$2,$3,1,'test','started','sending','smtp_started')`, id, revision, approval); e != nil {
		t.Fatal(e)
	}
	if _, e = owner.Exec(ctx, `UPDATE cheesetrap.delivery_attempts SET result='unknown',phase='recovery',classification='smtp_interrupted',finished_at=clock_timestamp() WHERE report_id=$1`, id); e != nil {
		t.Fatal(e)
	}
	for _, query := range []string{`UPDATE cheesetrap.delivery_attempts SET result='sent' WHERE report_id=$1`, `UPDATE cheesetrap.delivery_attempts SET message_id='changed' WHERE report_id=$1`, `DELETE FROM cheesetrap.delivery_attempts WHERE report_id=$1`} {
		if _, e = owner.Exec(ctx, query, id); e == nil {
			t.Fatal("history alteration allowed")
		}
	}
}
