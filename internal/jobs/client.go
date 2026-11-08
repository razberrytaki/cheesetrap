// Package jobs runs durable detection, window sealing and report drafting.
package jobs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"cheesetrap/internal/detection"
	"cheesetrap/internal/reporting"
	"cheesetrap/internal/store"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"
)

var ErrWorker = errors.New("worker_failed")

type DraftArgs struct{}

func (DraftArgs) Kind() string { return "draft_reports" }
func (DraftArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "drafts", UniqueOpts: activeUnique()}
}

type DetectionArgs struct{}

func (DetectionArgs) Kind() string { return "detect_events" }

type WindowArgs struct {
	WindowID string `json:"window_id"`
}

func (WindowArgs) Kind() string { return "seal_window" }
func activeUnique() river.UniqueOpts {
	return river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning, rivertype.JobStateRetryable, rivertype.JobStateScheduled,
	}}
}
func (DetectionArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "detection", UniqueOpts: activeUnique()}
}
func (WindowArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "windows", UniqueOpts: activeUnique()}
}

type detectionWorker struct {
	river.WorkerDefaults[DetectionArgs]
	pool *pgxpool.Pool
}

// A single finite aggregate may exceed the cooperative scheduling budget.
// Shutdown still cancels ctx and rolls back; timeouts must not retry the same
// large event forever before it can commit.
func (w *detectionWorker) Timeout(*river.Job[DetectionArgs]) time.Duration { return -1 }

func (w *detectionWorker) Work(ctx context.Context, _ *river.Job[DetectionArgs]) error {
	return runDetectionPasses(ctx, time.Now, func(ctx context.Context) error {
		return storageGate(ctx, w.pool)
	}, func(ctx context.Context) (detection.Progress, error) {
		return detection.ProcessBatchWithBudget(ctx, w.pool, 1000, time.Second)
	})
}

// Each pass commits and releases the cursor before the next gate or pass. The
// 20-second horizon yields between completed passes. Both it
// and the one-second transaction budget are cooperative: one complete event
// can exceed a budget, but no new pass starts after the horizon.
func runDetectionPasses(ctx context.Context, now func() time.Time, gate func(context.Context) error, pass func(context.Context) (detection.Progress, error)) error {
	deadline := now().Add(20 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !now().Before(deadline) {
			return river.JobSnooze(time.Second)
		}
		if err := gate(ctx); err != nil {
			return err
		}
		// Storage probing may consume the remaining time or observe cancellation.
		if err := ctx.Err(); err != nil {
			return err
		}
		if !now().Before(deadline) {
			return river.JobSnooze(time.Second)
		}
		progress, err := pass(ctx)
		if err != nil {
			return err
		}
		if !progress.HasMore {
			return nil
		}
	}
}

type windowWorker struct {
	river.WorkerDefaults[WindowArgs]
	pool *pgxpool.Pool
}

type draftWorker struct {
	river.WorkerDefaults[DraftArgs]
	pool    *pgxpool.Pool
	service *reporting.DraftService
}

func (w *draftWorker) Timeout(*river.Job[DraftArgs]) time.Duration { return -1 }
func (w *draftWorker) Work(ctx context.Context, _ *river.Job[DraftArgs]) error {
	if err := storageGate(ctx, w.pool); err != nil {
		return err
	}
	progress, err := w.service.Next(ctx)
	if err != nil {
		return err
	}
	if progress.More {
		return river.JobSnooze(time.Second)
	}
	return nil
}

func (w *windowWorker) Work(ctx context.Context, job *river.Job[WindowArgs]) error {
	if err := storageGate(ctx, w.pool); err != nil {
		return err
	}
	ready, err := reporting.SealWindow(ctx, w.pool, job.Args.WindowID)
	if err != nil {
		return err
	}
	if !ready {
		return river.JobSnooze(time.Second)
	}
	if _, err = river.ClientFromContext[pgx.Tx](ctx).Insert(ctx, DraftArgs{}, nil); err != nil {
		return workerError(ctx)
	}
	return nil
}

// NewClient uses the existing bounded application pool. Poll-only mode avoids
// reserving a listener connection; River's persistence still owns all jobs.
func NewClient(pool *pgxpool.Pool) (*river.Client[pgx.Tx], error) {
	if pool == nil {
		return nil, ErrWorker
	}
	workers := river.NewWorkers()
	river.AddWorker(workers, &retentionWorker{pool: pool})
	river.AddWorker(workers, &detectionWorker{pool: pool})
	river.AddWorker(workers, &windowWorker{pool: pool})
	river.AddWorker(workers, &draftWorker{pool: pool, service: reporting.NewDraftService(pool)})
	river.AddWorker(workers, &contactRefreshWorker{pool: pool, service: reporting.NewContactRefreshService(pool)})
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Schema: "cheesetrap_river", Workers: workers, Queues: map[string]river.QueueConfig{"retention": {MaxWorkers: 1}, "detection": {MaxWorkers: 1}, "windows": {MaxWorkers: 1}, "drafts": {MaxWorkers: 1}, "contacts": {MaxWorkers: 1}},
		CompletedJobRetentionPeriod: 7 * 24 * time.Hour,
		PollOnly:                    true, FetchPollInterval: time.Second, JobTimeout: 30 * time.Second,
		// Index maintenance belongs to the operator; this runtime has no ownership
		// or MAINTAIN privileges. A non-nil empty list disables only reindexing.
		ReindexerIndexNames: []string{},
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		return nil, ErrWorker
	}
	return client, nil
}

// Run reconciles immediately at startup and every minute. Missed intervals are
// replayed in bounded transactions, yielding between passes. Cancellation waits
// for jobs and River services to stop before closing the owned pool.
func Run(ctx context.Context, url string, grace time.Duration) (result error) {
	if grace <= 0 || grace > 5*time.Minute {
		return ErrWorker
	}
	pool, err := store.NewPool(ctx, url)
	if err != nil {
		return err
	}
	defer pool.Close()
	client, err := NewClient(pool)
	if err != nil {
		return err
	}
	if err = client.Start(ctx); err != nil {
		return workerError(ctx)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		if err := client.StopAndCancel(stopCtx); err != nil {
			result = ErrWorker
		}
	}()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			more, err := Reconcile(ctx, pool, client)
			if err != nil {
				if ctx.Err() != nil {
					continue
				}
				return ErrWorker
			}
			delay := time.Minute
			if more {
				delay = 100 * time.Millisecond
			}
			timer.Reset(delay)
		}
	}
}
func workerError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrWorker
}
