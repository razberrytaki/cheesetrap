// Package reporting freezes ingestion-time report membership before drafting.
package reporting

import (
	"context"
	"errors"
	"time"

	"cheesetrap/internal/store/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrWindow = errors.New("report_window_failed")

const CatchUpLimit = 32

type Reconciliation struct {
	Windows          []pgtype.UUID
	DetectionPending bool
	More             bool
}

// ReconcileTx must be committed together with the caller's River InsertTx calls.
// Lock order is shared with collector and detection: processing cursor first.
// Each pass advances at most 32 elapsed calendar intervals. The returned
// newly sealed windows must all be registered before commit. Database I/O is
// the only work inside this transaction.
func ReconcileTx(ctx context.Context, tx pgx.Tx) (Reconciliation, error) {
	q := db.New(tx)
	cursors, err := q.LockProcessingCursors(ctx)
	if err != nil {
		return Reconciliation{}, windowError(ctx)
	}
	start, now, err := initializeSchedule(ctx, q)
	if err != nil {
		return Reconciliation{}, windowError(ctx)
	}
	result := Reconciliation{DetectionPending: cursors.DetectedSeq < cursors.IngestedSeq}
	for n := 0; n < CatchUpLimit; n++ {
		w, err := q.GetReportWindowAt(ctx, start)
		if errors.Is(err, pgx.ErrNoRows) {
			schedule, e := q.ReportScheduleAt(ctx, start)
			if e != nil {
				return result, windowError(ctx)
			}
			end, e := nextBoundary(start.Time, schedule.Timezone, int(schedule.PeriodDays))
			if e != nil {
				return result, ErrWindow
			}
			w, err = q.EnsureReportWindow(ctx, db.EnsureReportWindowParams{StartAt: start, EndAt: stamp(end), SettingsVersion: schedule.Version})
		}
		if err != nil {
			return result, windowError(ctx)
		}
		if w.EndAt.Time.After(now.Time) {
			break
		}
		if _, err = seal(ctx, q, w, now, false, cursors.DetectedSeq); err != nil {
			return result, err
		}
		// Every interval sealed in this transaction must have its job registered
		// in that same transaction, even while older jobs fill the repair page.
		if w.State == "open" {
			result.Windows = append(result.Windows, w.WindowID)
		}
		start = w.EndAt
		result.More = n == CatchUpLimit-1
	}
	if err = q.SetReportScheduleCursor(ctx, start); err != nil {
		return result, windowError(ctx)
	}
	return result, nil
}

// SealWindow retries safely after interruption. It never marks a window ready
// from a maximum event sequence: the continuous detection cursor is required.
func SealWindow(ctx context.Context, pool *pgxpool.Pool, id string) (bool, error) {
	var windowID pgtype.UUID
	if err := windowID.Scan(id); err != nil || !windowID.Valid || pool == nil {
		return false, ErrWindow
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, windowError(ctx)
	}
	defer tx.Rollback(context.Background())
	q := db.New(tx)
	cursors, err := q.LockProcessingCursors(ctx)
	if err != nil {
		return false, windowError(ctx)
	}
	w, err := q.LockReportWindow(ctx, windowID)
	if err != nil {
		return false, windowError(ctx)
	}
	now, err := q.ReportingClock(ctx)
	if err != nil {
		return false, windowError(ctx)
	}
	ready, err := seal(ctx, q, w, now, true, cursors.DetectedSeq)
	if err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, windowError(ctx)
	}
	return ready, nil
}
func seal(ctx context.Context, q *db.Queries, w db.CheesetrapReportWindow, now pgtype.Timestamptz, finalize bool, detected int64) (bool, error) {
	if w.State == "ready" {
		return true, nil
	}
	if w.EndAt.Time.After(now.Time) {
		return false, nil
	}
	if w.State == "open" {
		// The common lock proves these are committed events. The time filter excludes
		// later-window ingestions already committed before delayed reconciliation.
		seq, err := q.ReportSealSequence(ctx, w.EndAt)
		if err != nil {
			return false, windowError(ctx)
		}
		w, err = q.SetReportWindowSealed(ctx, db.SetReportWindowSealedParams{WindowID: w.WindowID, SealedSeq: &seq})
		if err != nil {
			return false, windowError(ctx)
		}
		// A clock rollback must never let future collector batches enter this window.
		if err = q.AdvanceSealedBefore(ctx, w.EndAt); err != nil {
			return false, windowError(ctx)
		}
	}
	if !finalize || w.SealedSeq == nil || detected < *w.SealedSeq {
		return false, nil
	}
	n, err := q.SetReportWindowReady(ctx, db.SetReportWindowReadyParams{WindowID: w.WindowID, SealedSeq: &detected})
	if err != nil || n != 1 {
		return false, windowError(ctx)
	}
	return true, nil
}
func stamp(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t.UTC(), Valid: true} }
func windowError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrWindow
}
