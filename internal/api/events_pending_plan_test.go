//go:build integration

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"cheesetrap/internal/store/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pendingQueryCapture struct {
	sql  string
	args []any
}

func (c *pendingQueryCapture) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "-- name: ListAPIEvents :many") || strings.Contains(data.SQL, "-- name: ListAPIPendingEvents :many") {
		c.sql = data.SQL
		c.args = append([]any(nil), data.Args...)
	}
	return ctx
}
func (*pendingQueryCapture) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

type pendingQueryPlan struct {
	NodeType  string  `json:"Node Type"`
	Relation  string  `json:"Relation Name"`
	IndexCond string  `json:"Index Cond"`
	Rows      float64 `json:"Actual Rows"`
	Loops     float64 `json:"Actual Loops"`
	Removed   float64 `json:"Rows Removed by Filter"`
	Hit       float64 `json:"Shared Hit Blocks"`
	Read      float64 `json:"Shared Read Blocks"`
	Plans     []pendingQueryPlan
}

func (p pendingQueryPlan) work() (visited float64, seek bool) {
	if p.Relation == "events" {
		visited = (p.Rows + p.Removed) * p.Loops
		seek = strings.Contains(p.NodeType, "Index") && strings.Contains(p.IndexCond, "ingestion_seq >")
	}
	for _, child := range p.Plans {
		n, s := child.work()
		visited += n
		seek = seek || s
	}
	return
}

// Assert plan work, not machine-dependent elapsed time. Both plan-cache modes
// must seek beyond the processing boundary instead of visiting retained rows.
func TestPendingEventsUseSequenceRange(t *testing.T) {
	f := newReviewFixtureDomain(t, "EVENTRESULT")
	ctx := context.Background()
	const sensor = "10000000-0000-4000-8000-000000000505"
	const generation = "20000000-0000-4000-8000-000000000505"
	const base int64 = 2000000000000000
	const retained = 100000
	var ingested, detected int64
	if err := f.owner.QueryRow(ctx, "SELECT ingested_seq,detected_seq FROM cheesetrap.processing_cursors").Scan(&ingested, &detected); err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := f.owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"DELETE FROM cheesetrap.events WHERE sensor_id=$1", []any{sensor}},
			{"DELETE FROM cheesetrap.file_generations WHERE sensor_id=$1", []any{sensor}},
			{"DELETE FROM cheesetrap.sensors WHERE sensor_id=$1", []any{sensor}},
			{"DELETE FROM cheesetrap.report_windows WHERE window_id=$1", []any{f.window}},
			{"UPDATE cheesetrap.processing_cursors SET ingested_seq=$1,detected_seq=$2", []any{ingested, detected}},
		} {
			if _, err := f.owner.Exec(ctx, q.sql, q.args...); err != nil {
				t.Error(err)
			}
		}
	})
	exec("INSERT INTO cheesetrap.sensors(sensor_id,name,engine) VALUES($1,'pending-plan','cowrie')", sensor)
	exec("INSERT INTO cheesetrap.file_generations(file_generation_id,sensor_id,path,device,inode) VALUES($1,$2,'/test/pending-plan',1,1)", generation, sensor)
	exec(`INSERT INTO cheesetrap.events(sensor_id,file_generation_id,byte_offset,ingestion_seq,schema_version,engine,service,event_type,attributes,raw_hash)
 SELECT $1,$2,n,$3::bigint+n,1,'cowrie','ssh','pending.plan','{}',repeat('a',64) FROM generate_series(1,$4::integer) n`, sensor, generation, base, retained)
	exec("UPDATE cheesetrap.processing_cursors SET ingested_seq=$1,detected_seq=$1", base+retained)
	exec("ANALYZE cheesetrap.events")
	capture := &pendingQueryCapture{}
	cfg := f.api.Config()
	cfg.ConnConfig.Tracer = capture
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	page := decodeReview(t, request(NewHandler(pool, testOrigin), "GET", "/api/v1/events?detection_result=pending&event_type=pending.plan&limit=50", "", nil, f.cookies...), 200)
	if len(page["items"].([]any)) != 0 || capture.sql == "" {
		t.Fatal("caught-up pending query was not captured or returned rows")
	}
	// PREPARE/EXECUTE forces the real custom and generic query paths. Only the
	// known test arguments are rendered; no user-controlled SQL is interpolated.
	literals := make([]string, len(capture.args))
	for i, arg := range capture.args {
		switch v := arg.(type) {
		case int64:
			literals[i] = fmt.Sprint(v)
		case int32:
			literals[i] = fmt.Sprint(v)
		case *string:
			if v == nil {
				literals[i] = "NULL"
			} else {
				literals[i] = "'" + strings.ReplaceAll(*v, "'", "''") + "'"
			}
		case pgtype.Timestamptz:
			if v.Valid {
				t.Fatal("unexpected timestamp filter")
			}
			literals[i] = "NULL"
		default:
			if arg == nil || (reflect.ValueOf(arg).Kind() == reflect.Pointer && reflect.ValueOf(arg).IsNil()) {
				literals[i] = "NULL"
			} else {
				t.Fatalf("unexpected argument %T", arg)
			}
		}
	}
	for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := f.owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, "SET LOCAL plan_cache_mode="+mode); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, "PREPARE pending_event_work AS "+capture.sql); err != nil {
				t.Fatal(err)
			}
			defer tx.Exec(ctx, "DEALLOCATE pending_event_work")
			explain := `EXPLAIN (ANALYZE,BUFFERS,TIMING OFF,FORMAT JSON) EXECUTE pending_event_work(` + strings.Join(literals, ",") + ")"
			var raw []byte
			if err = tx.QueryRow(ctx, explain).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var plans []struct{ Plan pendingQueryPlan }
			if err = json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
				t.Fatalf("invalid plan: %v", err)
			}
			visits, seek := plans[0].Plan.work()
			t.Logf("retained=%d visited=%v sequence_seek=%v blocks=%v", retained, visits, seek, plans[0].Plan.Hit+plans[0].Plan.Read)
			if visits != 0 || !seek || plans[0].Plan.Hit+plans[0].Plan.Read > 64 {
				t.Fatalf("pending inspected retained rows: visits=%v seek=%v blocks=%v; %s", visits, seek, plans[0].Plan.Hit+plans[0].Plan.Read, raw)
			}
			// A transaction-local classifier that always fails proves the pending query
			// does not execute opaque evidence/history work, even through nested SQL.
			if _, err = tx.Exec(ctx, `CREATE OR REPLACE FUNCTION cheesetrap.event_detection_result(id uuid,seq bigint,processed bigint) RETURNS text LANGUAGE plpgsql STABLE AS $$ BEGIN RAISE EXCEPTION 'pending_must_not_read_evidence'; END $$`); err != nil {
				t.Fatal(err)
			}
			if err = tx.QueryRow(ctx, explain).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			// Unfiltered pages also classify pending rows without invoking evidence SQL.
			unfiltered, err := db.New(tx).ListAPIEvents(ctx, db.ListAPIEventsParams{Snapshot: base + retained, DetectedSnapshot: base - 1, PageLimit: 1})
			if err != nil || len(unfiltered) != 1 || unfiltered[0].DetectionResult != "pending" {
				t.Fatalf("unfiltered pending lookup invoked evidence: %v", err)
			}
		})
	}
}
