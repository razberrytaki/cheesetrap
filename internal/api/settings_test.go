//go:build integration

package api

import (
	"context"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type settingsReadTraceKey struct{}
type settingsReadTracer struct {
	matches   func(string) bool
	afterRead func()
	once      sync.Once
}

func (t *settingsReadTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, settingsReadTraceKey{}, t.matches(data.SQL))
}
func (t *settingsReadTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if matched, _ := ctx.Value(settingsReadTraceKey{}).(bool); matched && data.Err == nil {
		t.once.Do(t.afterRead)
	}
}
func settingsTracedHandler(t *testing.T, f *reviewFixture, tracer *settingsReadTracer) http.Handler {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(os.Getenv("CHEESETRAP_TEST_REVIEW_API_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return NewHandler(pool, testOrigin)
}

func TestReviewAPISettingsSnapshot(t *testing.T) {
	f := newReviewFixture(t)
	t.Run("concurrent_patch_returns_one_committed_snapshot", func(t *testing.T) {
		before := decodeReview(t, f.get("/api/v1/settings"), 200)
		interleaved := false
		// The trace hook changes real persisted state after the first settings read.
		// It also works when the whole response is read by one SQL statement.
		h := settingsTracedHandler(t, f, &settingsReadTracer{
			matches: func(sql string) bool { return strings.Contains(sql, "cheesetrap.settings") },
			afterRead: func() {
				decodeReview(t, f.mutate("PATCH", "/api/v1/settings", "settings-snapshot-interleave", map[string]any{"expected_version": before["version"], "timezone": "Asia/Tokyo"}), 200)
				interleaved = true
			},
		})
		got := decodeReview(t, request(h, "GET", "/api/v1/settings", "", nil, f.cookies...), 200)
		after := decodeReview(t, f.get("/api/v1/settings"), 200)
		if !interleaved || before["version"] == after["version"] {
			t.Fatal("concurrent PATCH fixture did not commit")
		}
		if !reflect.DeepEqual(got, before) && !reflect.DeepEqual(got, after) {
			t.Fatalf("GET mixed committed settings snapshots: version=%v schedule=%v pending=%v; before=%v after=%v", got["version"], got["schedule_version"], got["pending_schedule"], before["version"], after["version"])
		}
	})
	t.Run("schedule_boundary_uses_one_reference_time", func(t *testing.T) {
		var transition string
		var boundary time.Time
		if err := f.owner.QueryRow(f.ctx, `INSERT INTO cheesetrap.reporting_schedule_versions(timezone,period_days,effective_from) VALUES('UTC',1,clock_timestamp()+interval '2 seconds') RETURNING version::text,effective_from`).Scan(&transition, &boundary); err != nil {
			t.Fatal(err)
		}
		defer f.owner.Exec(f.ctx, `DELETE FROM cheesetrap.reporting_schedule_versions WHERE version=$1`, transition)
		crossed := false
		h := settingsTracedHandler(t, f, &settingsReadTracer{
			matches: func(sql string) bool { return strings.Contains(sql, "cheesetrap.reporting_schedule_versions") },
			afterRead: func() {
				var beforeBoundary bool
				if err := f.owner.QueryRow(f.ctx, `SELECT clock_timestamp()<$1`, boundary).Scan(&beforeBoundary); err != nil || !beforeBoundary {
					t.Fatal("schedule read did not precede fixture boundary", err)
				}
				if _, err := f.owner.Exec(f.ctx, `SELECT pg_sleep(greatest(0,extract(epoch FROM $1::timestamptz-clock_timestamp()))+0.02)`, boundary); err != nil {
					t.Fatal(err)
				}
				crossed = true
			},
		})
		got := decodeReview(t, request(h, "GET", "/api/v1/settings", "", nil, f.cookies...), 200)
		if !crossed {
			t.Fatal("schedule boundary hook did not run")
		}
		active := got["active_schedule"].(map[string]any)["version"]
		var pending any
		if v, ok := got["pending_schedule"].(map[string]any); ok {
			pending = v["version"]
		}
		// At every instant this immediate transition is either the first pending
		// schedule or the active schedule. It can never be both or be skipped.
		if (active == transition) == (pending == transition) {
			t.Fatalf("GET skipped or duplicated schedule across time boundary: active=%v pending=%v transition=%v", active, pending, transition)
		}
	})
}
