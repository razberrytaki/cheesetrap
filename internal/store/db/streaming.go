package db

// Handwritten bounded traversal of sqlc-owned queries. Query text and result
// shapes remain generated from internal/store/queries; no generated file is
// edited. These methods require a transaction, since cursors live until commit.
import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func (q *Queries) Queryer() DBTX { return q.db }

func (q *Queries) HasReportCandidateEvidence(ctx context.Context, arg ListReportCandidateEvidenceParams) (bool, error) {
	var exists bool
	err := q.db.QueryRow(ctx, "SELECT EXISTS("+listReportCandidateEvidence+")", arg.WindowID, arg.SourceIp).Scan(&exists)
	return exists, err
}

// A loaded revision may be consumed outside a command transaction. In that
// case pin a read transaction for the cursor; never rely on pool affinity.
func (q *Queries) VisitLegacyReportContents(ctx context.Context, revision, kind string, f func([]byte) error) error {
	reader := q
	if pool, ok := q.db.(*pgxpool.Pool); ok {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(context.Background())
		reader = New(tx)
	}
	type entry struct{ Entry []byte }
	return visitCursor(ctx, reader, "legacy_report_scan", `SELECT x.entry FROM cheesetrap.report_revisions v CROSS JOIN LATERAL jsonb_array_elements(nullif(v.snapshot->$2::text,'null')) WITH ORDINALITY x(entry,n) WHERE v.revision_id=$1 ORDER BY x.n`, 1, []any{revision, kind}, func(page []entry) error {
		for _, v := range page {
			if err := f(v.Entry); err != nil {
				return err
			}
		}
		return nil
	})
}

func visitCursor[T any](ctx context.Context, q *Queries, name, query string, size int, args []any, f func([]T) error) error {
	// Names and FETCH sizes are fixed internal constants, never caller data.
	if _, err := q.db.Exec(ctx, "DECLARE "+name+" NO SCROLL CURSOR FOR "+query, args...); err != nil {
		return err
	}
	defer q.db.Exec(ctx, "CLOSE "+name)
	fetch := "FETCH FORWARD 32 FROM " + name
	if size == 1 {
		fetch = "FETCH FORWARD 1 FROM " + name
	}
	for {
		rows, err := q.db.Query(ctx, fetch)
		if err != nil {
			return err
		}
		page, err := pgx.CollectRows(rows, pgx.RowToStructByName[T])
		if err != nil {
			return err
		}
		if len(page) == 0 {
			return nil
		}
		if err = f(page); err != nil {
			return err
		}
	}
}
func (q *Queries) VisitReportSourceDetections(ctx context.Context, arg ListReportSourceDetectionsParams, f func([]ListReportSourceDetectionsRow) error) error {
	return visitCursor(ctx, q, "report_rule_scan", listReportSourceDetections, 1, []any{arg.WindowID, arg.SourceIp}, f)
}
func (q *Queries) VisitReportCandidateEvidence(ctx context.Context, arg ListReportCandidateEvidenceParams, f func([]CheesetrapEvent) error) error {
	return visitCursor(ctx, q, "report_evidence_scan", listReportCandidateEvidence, 32, []any{arg.WindowID, arg.SourceIp}, f)
}
