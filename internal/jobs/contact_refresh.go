package jobs

import (
	"context"
	"io"
	"log/slog"
	"time"

	"cheesetrap/internal/reporting"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

type ContactRefreshArgs struct {
	RequestID string `json:"request_id"`
}

func (ContactRefreshArgs) Kind() string { return "refresh_contact" }
func (ContactRefreshArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "contacts", UniqueOpts: activeUnique()}
}

type contactRefreshWorker struct {
	river.WorkerDefaults[ContactRefreshArgs]
	pool    *pgxpool.Pool
	service *reporting.ContactRefreshService
}

func (w *contactRefreshWorker) Timeout(*river.Job[ContactRefreshArgs]) time.Duration {
	// The lookup has its own deadline; rebuilding a retained proof does not.
	return -1
}
func (w *contactRefreshWorker) Work(ctx context.Context, job *river.Job[ContactRefreshArgs]) error {
	if err := storageGate(ctx, w.pool); err != nil {
		return err
	}
	return w.service.Process(ctx, job.Args.RequestID)
}

// NewProducer has no queues or workers and must never be started. Its database
// role needs only the pinned InsertTx statement's table/sequence privileges.
func NewProducer(pool *pgxpool.Pool) (*river.Client[pgx.Tx], error) {
	if pool == nil {
		return nil, ErrWorker
	}
	c, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: "cheesetrap_river", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		return nil, ErrWorker
	}
	return c, nil
}
func repairContactRefreshes(ctx context.Context, tx pgx.Tx, client *river.Client[pgx.Tx]) (bool, error) {
	rows, err := tx.Query(ctx, `SELECT f.request_id::text FROM cheesetrap.contact_refresh_requests f WHERE f.status='queued' AND NOT EXISTS(SELECT 1 FROM cheesetrap_river.river_job j WHERE j.kind='refresh_contact' AND j.args @> jsonb_build_object('request_id',f.request_id::text) AND j.state IN ('available','pending','running','retryable','scheduled')) ORDER BY f.created_at,f.request_id LIMIT $1`, reporting.CatchUpLimit+1)
	if err != nil {
		return false, workerError(ctx)
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return false, workerError(ctx)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if rows.Err() != nil {
		return false, workerError(ctx)
	}
	more := len(ids) > reporting.CatchUpLimit
	if more {
		ids = ids[:reporting.CatchUpLimit]
	}
	for _, id := range ids {
		if _, err = client.InsertTx(ctx, tx, ContactRefreshArgs{RequestID: id}, nil); err != nil {
			return false, workerError(ctx)
		}
	}
	return more, nil
}
