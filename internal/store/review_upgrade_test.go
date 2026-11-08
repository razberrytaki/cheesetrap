//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"cheesetrap/internal/store"
	"cheesetrap/migrations"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestReviewUpgradePreservesSettings(t *testing.T) {
	ctx := context.Background()
	url := os.Getenv("CHEESETRAP_TEST_REVIEW_UPGRADE_MIGRATION_URL")
	pool, err := store.NewPool(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	sql := stdlib.OpenDBFromPool(pool)
	provider, err := goose.NewProvider(goose.DialectPostgres, sql, migrations.Files, goose.WithTableName("cheesetrap.goose_db_version"), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.UpTo(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO cheesetrap.settings(key,version,value) VALUES('reporting_reply_to',17,'{"address":"existing@example.org"}');INSERT INTO cheesetrap.reporting_schedule_versions(timezone,period_days,effective_from) VALUES('America/New_York',7,clock_timestamp()+interval '1 day')`); err != nil {
		t.Fatal(err)
	}
	if err = provider.Close(); err != nil {
		t.Fatal(err)
	}
	if err = store.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	var data []byte
	var replyVersion int64
	if err = pool.QueryRow(ctx, `SELECT value,(SELECT version FROM cheesetrap.settings WHERE key='reporting_reply_to') FROM cheesetrap.settings WHERE key='review_policy'`).Scan(&data, &replyVersion); err != nil {
		t.Fatal(err)
	}
	var v struct {
		ReplyTo         string `json:"reply_to"`
		Timezone        string `json:"timezone"`
		PeriodDays      int    `json:"period_days"`
		ScheduleVersion string `json:"schedule_version"`
	}
	if json.Unmarshal(data, &v) != nil || v.ReplyTo != "existing@example.org" || v.Timezone != "America/New_York" || v.PeriodDays != 7 || v.ScheduleVersion != "2" || replyVersion != 17 {
		t.Fatalf("upgrade lost existing configuration: %+v version=%d", v, replyVersion)
	}
}
