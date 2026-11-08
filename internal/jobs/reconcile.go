package jobs

import (
	"context"

	"cheesetrap/internal/reporting"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
)

// Reconcile repairs missing, cancelled and discarded jobs from durable domain
// state. Active-only River uniqueness admits a replacement for any terminal job
// while preventing duplicate active work. Domain changes and InsertTx share one
// transaction, so a failed insert never advances the durable schedule cursor.
func Reconcile(ctx context.Context, pool *pgxpool.Pool, client *river.Client[pgx.Tx]) (bool, error) {
	if pool == nil || client == nil {
		return false, ErrWorker
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, workerError(ctx)
	}
	defer tx.Rollback(context.Background())
	progress, err := reporting.ReconcileTx(ctx, tx)
	if err != nil {
		return false, err
	}
	if progress.DetectionPending {
		if _, err = client.InsertTx(ctx, tx, DetectionArgs{}, nil); err != nil {
			return false, workerError(ctx)
		}
	}
	for _, id := range progress.Windows {
		if _, err = client.InsertTx(ctx, tx, WindowArgs{WindowID: id.String()}, nil); err != nil {
			return false, workerError(ctx)
		}
	}
	// Exclude active jobs before applying the repair limit. Otherwise an old
	// page of waiting jobs could indefinitely hide a later missing job. This
	// queue-specific join intentionally lives here rather than in the domain
	// catalog: River's pinned official schema is owned by its own migrator.
	rows, err := tx.Query(ctx, `SELECT w.window_id::text FROM cheesetrap.report_windows w
 WHERE w.state='sealed' AND NOT EXISTS(
  SELECT 1 FROM cheesetrap_river.river_job j WHERE j.kind='seal_window'
   AND j.args @> jsonb_build_object('window_id',w.window_id::text)
   AND j.state IN ('available','pending','running','retryable','scheduled'))
 ORDER BY w.start_at LIMIT $1`, reporting.CatchUpLimit)
	if err != nil {
		return false, workerError(ctx)
	}
	repair := make([]string, 0, reporting.CatchUpLimit)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return false, workerError(ctx)
		}
		repair = append(repair, id)
	}
	rows.Close()
	if rows.Err() != nil {
		return false, workerError(ctx)
	}
	for _, id := range repair {
		if _, err = client.InsertTx(ctx, tx, WindowArgs{WindowID: id}, nil); err != nil {
			return false, workerError(ctx)
		}
	}
	var draftPending bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cheesetrap.report_windows w WHERE w.state='ready' AND NOT EXISTS(SELECT 1 FROM cheesetrap.report_window_completions c WHERE c.window_id=w.window_id))`).Scan(&draftPending); err != nil {
		return false, workerError(ctx)
	}
	if draftPending {
		if _, err = client.InsertTx(ctx, tx, DraftArgs{}, nil); err != nil {
			return false, workerError(ctx)
		}
	}
	refreshMore, err := repairContactRefreshes(ctx, tx, client)
	if err != nil {
		return false, err
	}
	if _, err = client.InsertTx(ctx, tx, RetentionArgs{}, nil); err != nil {
		return false, workerError(ctx)
	}
	if err = tx.Commit(ctx); err != nil {
		return false, workerError(ctx)
	}
	return progress.More || refreshMore, nil
}
