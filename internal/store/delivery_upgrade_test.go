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

func TestDeliveryUpgradePreservesRevision(t *testing.T) {
	ctx := context.Background()
	url := os.Getenv("CHEESETRAP_TEST_DELIVERY_UPGRADE_MIGRATION_URL")
	owner, err := store.NewPool(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(owner), migrations.Files, goose.WithTableName("cheesetrap.goose_db_version"), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.UpTo(ctx, 8); err != nil {
		t.Fatal(err)
	}
	id, revision, digest, actor, err := reporting.SeedLegacyRevision(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.UpTo(ctx, 9); err != nil {
		t.Fatal(err)
	}
	var approval string
	if err = owner.QueryRow(ctx, `INSERT INTO cheesetrap.approvals(report_id,revision_id,content_digest,admin_id,settings_version,schedule_version,approved_at,scheduled_at) VALUES($1,$2,$3,$4,1,1,clock_timestamp(),clock_timestamp()+interval '1 day') RETURNING approval_id::text`, id, revision, digest, actor).Scan(&approval); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Exec(ctx, `UPDATE cheesetrap.reports SET version=version+1,state='queued' WHERE report_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err = provider.Close(); err != nil {
		t.Fatal(err)
	}
	if err = store.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	var gotID, gotDigest, state string
	var version int64
	if err = owner.QueryRow(ctx, `SELECT current_revision_id::text,r.version,r.state,v.content_digest FROM cheesetrap.reports r JOIN cheesetrap.report_revisions v ON v.revision_id=r.current_revision_id WHERE r.report_id=$1`, id).Scan(&gotID, &version, &state, &gotDigest); err != nil || gotID != revision || version != 2 || state != "queued" || digest != gotDigest {
		t.Fatal("upgrade mutated revision", err)
	}
	var mode string
	var exception bool
	if err = owner.QueryRow(ctx, `SELECT mode,stale_reconfirmed FROM cheesetrap.approvals WHERE approval_id=$1 AND invalidated_at IS NULL`, approval).Scan(&mode, &exception); err != nil || mode != "manual" || exception {
		t.Fatal("upgrade altered approval", mode, exception, err)
	}
	for _, role := range []string{"API", "WORKER", "COLLECTOR"} {
		pool, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_DELIVERY_UPGRADE_"+role+"_URL"))
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		var read, insert, slotUpdate, invalidate, del bool
		if err = pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,'cheesetrap.approvals','SELECT'),has_table_privilege(current_user,'cheesetrap.approvals','INSERT'),has_column_privilege(current_user,'cheesetrap.approvals','scheduled_at','UPDATE'),has_column_privilege(current_user,'cheesetrap.approvals','invalidated_at','UPDATE'),has_table_privilege(current_user,'cheesetrap.approvals','DELETE')`).Scan(&read, &insert, &slotUpdate, &invalidate, &del); err != nil {
			t.Fatal(err)
		}
		var policyRead, policyWrite bool
		if err = pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,'cheesetrap.automatic_policy','SELECT'),has_column_privilege(current_user,'cheesetrap.automatic_policy','singleton','UPDATE')`).Scan(&policyRead, &policyWrite); err != nil {
			t.Fatal(err)
		}
		allowed := role != "COLLECTOR"
		if policyRead != allowed || policyWrite != allowed {
			t.Fatal("automatic policy role privileges", role)
		}
		if read != allowed || insert != allowed || invalidate != allowed || slotUpdate || del {
			t.Fatal("approval privileges", role, read, insert, slotUpdate, invalidate, del)
		}
	}
}
