package jobs

import (
	"cheesetrap/internal/observability"
	"cheesetrap/internal/retention"
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"time"
)

type RetentionArgs struct{}

func (RetentionArgs) Kind() string { return "retention_cleanup" }
func (RetentionArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "retention", UniqueOpts: activeUnique()}
}

type retentionWorker struct {
	river.WorkerDefaults[RetentionArgs]
	pool *pgxpool.Pool
}

func (w *retentionWorker) Work(ctx context.Context, _ *river.Job[RetentionArgs]) error {
	return runRetentionPasses(ctx, time.Now, func(ctx context.Context) error {
		// Cleanup must free space even when ingestion is storage-restricted.
		_, err := observability.Sample(ctx, w.pool, "worker", observability.ConfiguredStorage())
		return err
	}, func(ctx context.Context) (retention.Progress, error) {
		return retention.Cleanup(ctx, w.pool, time.Now().UTC(), 1000)
	}, yieldRetention)
}

// Every pass is a separately committed transaction. Yielding after progress
// releases the cursor and draft locks for ingestion and reporting. The horizon
// leaves room for one final five-second SQL pass within River's 30-second limit.
func runRetentionPasses(ctx context.Context, now func() time.Time, sample func(context.Context) error, pass func(context.Context) (retention.Progress, error), yield func(context.Context) error) error {
	deadline := now().Add(20 * time.Second)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sample(ctx); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !now().Before(deadline) {
			return river.JobSnooze(time.Second)
		}
		progress, err := pass(ctx)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(err, retention.ErrBusy) {
			// Cleanup has rolled back and released its pool connection. Retry
			// within this job's remaining horizon without holding either lock.
			remaining := deadline.Sub(now())
			if remaining > 0 {
				if err := waitRetention(ctx, min(50*time.Millisecond, remaining)); err != nil {
					return err
				}
			}
			continue
		}
		if err != nil {
			return err
		}
		if progress.Deleted == 0 {
			return nil
		}
		if err := yield(ctx); err != nil {
			return err
		}
	}
}

func yieldRetention(ctx context.Context) error {
	return waitRetention(ctx, 10*time.Millisecond)
}

func waitRetention(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func storageGate(ctx context.Context, pool *pgxpool.Pool) error {
	restricted, err := observability.Sample(ctx, pool, "worker", observability.ConfiguredStorage())
	if err != nil {
		return err
	}
	if restricted {
		return river.JobSnooze(time.Minute)
	}
	return nil
}
