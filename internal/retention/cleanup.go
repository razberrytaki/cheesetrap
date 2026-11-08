// Package retention applies bounded database cleanup; it never removes engine files.
package retention

import (
	"cheesetrap/internal/policy"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type Policy = policy.Retention

func DefaultPolicy() Policy { return policy.Defaults().Retention }
func TerminalExpired(state string, changed time.Time, uncertain bool, now time.Time) bool {
	return (state == "closed_unconfirmed" || ((state == "sent" || state == "rejected") && !uncertain)) && changed.Before(now.Add(-180*24*time.Hour))
}

var ErrCleanup = errors.New("retention_cleanup_failed")

// ErrBusy means maintenance did not acquire its serialization locks. No cleanup
// ran; callers must retry rather than treating this as completed maintenance.
var ErrBusy = errors.New("retention_cleanup_busy")

type Progress struct {
	Deleted         int64
	ProtectedEvents int64
}

func Cleanup(ctx context.Context, pool *pgxpool.Pool, now time.Time, limit int) (Progress, error) {
	if pool == nil || limit < 1 || limit > 1000 || now.IsZero() {
		return Progress{}, ErrCleanup
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Progress{}, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return Progress{}, cleanupError(ctx)
	}
	defer tx.Rollback(ctx)
	// Acquire the same locks, in the same order, before starting destructive work.
	// A busy draft must release the already-acquired cursor on rollback. Keeping
	// both locks in this transaction prevents a check-then-act race with writers.
	for _, lock := range []struct{ acquire, exists string }{
		{`SELECT singleton FROM cheesetrap.processing_cursors WHERE singleton FOR UPDATE SKIP LOCKED`, `SELECT EXISTS(SELECT 1 FROM cheesetrap.processing_cursors WHERE singleton)`},
		{`SELECT singleton FROM cheesetrap.report_draft_lock WHERE singleton FOR UPDATE SKIP LOCKED`, `SELECT EXISTS(SELECT 1 FROM cheesetrap.report_draft_lock WHERE singleton)`},
	} {
		var singleton bool
		err = tx.QueryRow(ctx, lock.acquire).Scan(&singleton)
		if errors.Is(err, pgx.ErrNoRows) {
			// SKIP LOCKED must not disguise a missing required singleton as contention.
			if err = tx.QueryRow(ctx, lock.exists).Scan(&singleton); err != nil || !singleton {
				return Progress{}, cleanupError(ctx)
			}
			if err = tx.Rollback(ctx); err != nil {
				return Progress{}, cleanupError(ctx)
			}
			return Progress{}, ErrBusy
		}
		if err != nil || !singleton {
			return Progress{}, cleanupError(ctx)
		}
	}
	var p Progress
	if err = tx.QueryRow(ctx, `SELECT deleted,protected_events FROM cheesetrap.retention_cleanup($1,$2)`, now, limit).Scan(&p.Deleted, &p.ProtectedEvents); err != nil {
		return Progress{}, cleanupError(ctx)
	}
	if err = tx.Commit(ctx); err != nil {
		return Progress{}, cleanupError(ctx)
	}
	return p, nil
}

func cleanupError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrCleanup
}
