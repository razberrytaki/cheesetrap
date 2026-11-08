//go:build integration

package reporting_test

import (
	"context"
	"os"
	"testing"
	"time"

	"cheesetrap/internal/jobs"
	"cheesetrap/internal/reporting"
	"cheesetrap/internal/store"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A future database clock floor reproduces midnight DST while using production
// clock queries. Neither ChangeSchedule nor Reconcile accepts a test clock.
func TestScheduleMidnightDST(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pools := map[string]*pgxpool.Pool{}
	for _, role := range []string{"MIGRATION", "WORKER"} {
		url := os.Getenv("CHEESETRAP_TEST_REPORTING_" + role + "_URL")
		if url == "" {
			t.Fatal("isolated reporting credentials required")
		}
		pool, err := store.NewPool(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		pools[role] = pool
	}
	owner, worker := pools["MIGRATION"], pools["WORKER"]
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	var realNow time.Time
	var originalFloor pgtype.Timestamptz
	if err := owner.QueryRow(ctx, "SELECT clock_timestamp(),sealed_before FROM cheesetrap.processing_cursors").Scan(&realNow, &originalFloor); err != nil {
		t.Fatal(err)
	}
	clear := func() {
		exec("DELETE FROM cheesetrap.report_windows; DELETE FROM cheesetrap.reporting_schedule_versions WHERE version>1; DELETE FROM cheesetrap_river.river_job; UPDATE cheesetrap.reporting_schedule_cursor SET next_start=NULL")
	}
	clear()
	defer func() { clear(); exec("UPDATE cheesetrap.processing_cursors SET sealed_before=$1", originalFloor) }()
	// Santiago's future midnight spring transition is the first September Sunday.
	date := time.Date(realNow.Year()+1, 9, 1, 0, 0, 0, 0, time.UTC)
	date = date.AddDate(0, 0, (7-int(date.Weekday()))%7)
	anchor := date.AddDate(0, 0, -4).Add(4 * time.Hour)
	now := date.AddDate(0, 0, 1).Add(15 * time.Hour)
	wantEnd := date.AddDate(0, 0, 2).Add(3 * time.Hour)
	var version int64
	if err := owner.QueryRow(ctx, "INSERT INTO cheesetrap.reporting_schedule_versions(timezone,period_days,effective_from) VALUES('America/Santiago',2,$1) RETURNING version", anchor).Scan(&version); err != nil {
		t.Fatal(err)
	}
	exec("UPDATE cheesetrap.reporting_schedule_cursor SET next_start=$1", anchor)
	exec("UPDATE cheesetrap.processing_cursors SET sealed_before=$1", now)
	// No current window has been materialized: calculation must match later
	// catch-up rather than writing an effective boundary in the past.
	change, err := reporting.ChangeSchedule(ctx, worker, "Asia/Tokyo", 7)
	if err != nil || !change.EffectiveFrom.Time.Equal(wantEnd) || !change.EffectiveFrom.Time.After(now) {
		t.Fatalf("backlogged change effective=%s want=%s err=%v", change.EffectiveFrom.Time, wantEnd, err)
	}
	client, err := jobs.NewClient(worker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = jobs.Reconcile(ctx, worker, client); err != nil {
		t.Fatal(err)
	}
	var id, before, after string
	var currentVersion int64
	var start, end time.Time
	if err = owner.QueryRow(ctx, "SELECT window_id,start_at,end_at,settings_version,row_to_json(w)::text FROM cheesetrap.report_windows w WHERE start_at<=$1 AND end_at>$1", now).Scan(&id, &start, &end, &currentVersion, &before); err != nil {
		t.Fatal(err)
	}
	if !start.Equal(date.Add(4*time.Hour)) || !end.Equal(wantEnd) || currentVersion != version {
		t.Fatal("catch-up repartitioned the current DST interval")
	}
	second, err := reporting.ChangeSchedule(ctx, worker, "UTC", 3)
	if err != nil || !second.EffectiveFrom.Time.Equal(wantEnd) {
		t.Fatal("materialized interval changed the effective boundary", err)
	}
	if _, err = jobs.Reconcile(ctx, worker, client); err != nil {
		t.Fatal(err)
	}
	if err = owner.QueryRow(ctx, "SELECT row_to_json(w)::text FROM cheesetrap.report_windows w WHERE window_id=$1", id).Scan(&after); err != nil || before != after {
		t.Fatal("settings change mutated the open interval")
	}
	var breaks int
	if err = owner.QueryRow(ctx, "SELECT count(*) FROM (SELECT start_at,lag(end_at) OVER(ORDER BY start_at) prior FROM cheesetrap.report_windows) w WHERE prior IS NOT NULL AND prior<>start_at").Scan(&breaks); err != nil || breaks != 0 {
		t.Fatal("DST reconciliation left a gap or overlap")
	}
}
