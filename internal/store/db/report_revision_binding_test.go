package db_test

import (
	"bytes"
	"context"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
)

type revisionBindingCapture struct {
	db.DBTX
	sql  string
	args []any
}

func (c *revisionBindingCapture) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	c.sql, c.args = sql, args
	return revisionBindingRow{}
}

type revisionBindingRow struct{}

func (revisionBindingRow) Scan(...any) error { return nil }

func revisionBindingFixture(snapshot []byte) db.AppendReportRevisionParams {
	return db.AppendReportRevisionParams{ReportID: pgtype.UUID{Bytes: [16]byte{1, 2, 3}, Valid: true}, Version: 7, Snapshot: snapshot, Subject: "distinct subject", Body: strings.Repeat("body", 8192), Recipient: "recipient@example.test", ReplyTo: "reply@example.test", HoldReasons: []string{"contact_missing", "evidence_incomplete"}, State: "held", AutoApprovalAllowed: true, BodyEdited: false, ContentDigest: strings.Repeat("a", 64)}
}

// Derive positions from the generated statement, independently of its argument
// list. This catches same-type swaps as well as an incorrect VALUES placeholder.
func captureRevisionBinding(t *testing.T, p db.AppendReportRevisionParams) (*revisionBindingCapture, []uint32) {
	t.Helper()
	c := &revisionBindingCapture{}
	if _, err := db.New(c).AppendReportRevision(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`report_revisions\(([^)]+)\) VALUES\(([^)]+)\)`).FindStringSubmatch(c.sql)
	if len(match) != 3 {
		t.Fatalf("unexpected revision INSERT: %s", c.sql)
	}
	columns, placeholders := strings.Split(match[1], ","), strings.Split(match[2], ",")
	expected := map[string]struct {
		value any
		oid   uint32
	}{
		"report_id": {p.ReportID, pgtype.UUIDOID}, "version": {p.Version, pgtype.Int8OID}, "snapshot": {p.Snapshot, pgtype.JSONBOID},
		"subject": {p.Subject, pgtype.TextOID}, "body": {p.Body, pgtype.TextOID}, "recipient": {p.Recipient, pgtype.TextOID}, "reply_to": {p.ReplyTo, pgtype.TextOID},
		"hold_reasons": {p.HoldReasons, pgtype.TextArrayOID}, "state": {p.State, pgtype.TextOID}, "auto_approval_allowed": {p.AutoApprovalAllowed, pgtype.BoolOID}, "body_edited": {p.BodyEdited, pgtype.BoolOID}, "content_digest": {p.ContentDigest, pgtype.TextOID},
	}
	if len(columns) != len(expected) || len(placeholders) != len(expected) || len(c.args) != len(expected) {
		t.Fatal("revision field count changed")
	}
	oids := make([]uint32, len(c.args))
	for i, column := range columns {
		want, ok := expected[column]
		if !ok {
			t.Fatalf("unexpected column %q", column)
		}
		position, err := strconv.Atoi(strings.TrimPrefix(placeholders[i], "$"))
		if err != nil || position < 1 || position > len(c.args) {
			t.Fatalf("invalid placeholder %q", placeholders[i])
		}
		position--
		if oids[position] != 0 {
			t.Fatalf("duplicate placeholder %q", placeholders[i])
		}
		if !reflect.DeepEqual(c.args[position], want.value) {
			t.Fatalf("column %s has wrong argument at %s", column, placeholders[i])
		}
		oids[position] = want.oid
		delete(expected, column)
	}
	if len(expected) != 0 {
		t.Fatalf("missing columns: %v", expected)
	}
	return c, oids
}

func TestReportRevisionBindingColumnMapping(t *testing.T) {
	captureRevisionBinding(t, revisionBindingFixture([]byte(`{"distinct":"snapshot"}`)))
}

func TestReportRevisionBindingAllocation(t *testing.T) {
	// A large valid JSON value followed by a 32 KiB body reproduces both pgx
	// parameter and Bind buffer growth. Measure actual generated query arguments.
	snapshot := append([]byte(`{"padding":"`), bytes.Repeat([]byte{'x'}, 16<<20)...)
	snapshot = append(snapshot, []byte(`"}`)...)
	c, oids := captureRevisionBinding(t, revisionBindingFixture(snapshot))
	m := pgtype.NewMap()
	var before, built, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var eqb pgx.ExtendedQueryBuilder
	if err := eqb.Build(m, &pgconn.StatementDescription{ParamOIDs: oids}, c.args); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&built)
	wire, err := (&pgproto3.Bind{PreparedStatement: "revision", ParameterFormatCodes: eqb.ParamFormats, Parameters: eqb.ParamValues, ResultFormatCodes: []int16{1}}).Encode(make([]byte, 0, 1024))
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	// One parameter copy and one wire copy, with generous allowance for small
	// fields, allocator rounding and race instrumentation. No timing/GC tuning.
	budget := uint64(len(snapshot))*5/2 + (1 << 20)
	t.Logf("snapshot=%d builder_alloc=%d bind_alloc=%d total=%d budget=%d", len(snapshot), built.TotalAlloc-before.TotalAlloc, after.TotalAlloc-built.TotalAlloc, allocated, budget)
	if allocated > budget {
		t.Errorf("revision binding allocated %d bytes, want <=%d (no duplicate large buffers)", allocated, budget)
	}
	var decoded pgproto3.Bind
	if err := decoded.Decode(wire[5:]); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Parameters, eqb.ParamValues) {
		t.Fatal("wire changed encoded parameter values")
	}
	runtime.KeepAlive(c)
	runtime.KeepAlive(eqb)
	runtime.KeepAlive(wire)
}
