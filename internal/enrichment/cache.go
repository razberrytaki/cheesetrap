package enrichment

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service shares exact-IP cached evidence and expiring claims across processes.
// Construction fixes all production network policy; transports and endpoints are
// intentionally not public options. This service never sends reports.
type Service struct {
	pool   *pgxpool.Pool
	lookup func(context.Context, string) (Result, error)
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, lookup: newResolver().lookup}
}

var errCache = errors.New("enrichment_cache_unavailable")
var errCacheInvalid = errors.New("enrichment_cache_invalid")

// Lookup never holds a transaction while querying a registry. A random database
// token fences completion and release, so an expired/cancelled owner cannot
// overwrite the result of a newer lookup. Waiting and external I/O share 30s.
func (s *Service) Lookup(parent context.Context, raw string) (Result, error) {
	return s.lookupFresh(parent, raw, time.Time{})
}

// Refresh reuses only a result obtained since this durable request. Negative
// cache lifetimes and Retry-After still apply, as do all production transport,
// address, timeout and fenced-lease policies. It opens no caller transaction.
func (s *Service) Refresh(parent context.Context, raw string, requestedAt time.Time) (Result, error) {
	if requestedAt.IsZero() {
		return Result{}, errCacheInvalid
	}
	return s.lookupFresh(parent, raw, requestedAt)
}
func (s *Service) lookupFresh(parent context.Context, raw string, requestedAt time.Time) (Result, error) {
	ctx, cancel := context.WithTimeout(parent, lookupTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	ip, ok := publicAddress(raw)
	if !ok {
		return held(raw, "address_not_public"), nil
	}
	if s == nil || s.pool == nil {
		return Result{}, errCache
	}
	q := db.New(s.pool)
	for {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		data, err := q.GetEnrichmentResult(ctx, ip)
		if err == nil {
			var r Result
			if decodeJSON(data, &r) != nil || r.SchemaVersion != 1 || r.Address != ip.String() || r.QueriedAt.IsZero() || !r.ExpiresAt.After(r.QueriedAt) {
				return Result{}, errCacheInvalid
			}
			if requestedAt.IsZero() || !r.LookupSucceeded || !r.QueriedAt.Before(requestedAt) || r.RetryAfter.After(time.Now()) {
				return r, nil
			}
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return Result{}, cacheError(ctx)
		}
		var claim db.ClaimEnrichmentRow
		if requestedAt.IsZero() {
			claim, err = q.ClaimEnrichment(ctx, db.ClaimEnrichmentParams{Address: ip, LeaseSeconds: int32((lookupTimeout + 5*time.Second) / time.Second)})
		} else {
			var refreshed db.ClaimRefreshEnrichmentRow
			refreshed, err = q.ClaimRefreshEnrichment(ctx, db.ClaimRefreshEnrichmentParams{Address: ip, LeaseSeconds: int32((lookupTimeout + 5*time.Second) / time.Second), RequestedAt: pgtype.Timestamptz{Time: requestedAt, Valid: true}})
			claim = db.ClaimEnrichmentRow(refreshed)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			timer := time.NewTimer(25 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return Result{}, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if err != nil {
			return Result{}, cacheError(ctx)
		}
		release := func() {
			// Cancellation must not strand an otherwise healthy process's claim. A
			// crashed process is recovered by the database lease expiry instead.
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer stop()
			_ = q.ReleaseEnrichment(cleanup, db.ReleaseEnrichmentParams{Address: ip, LeaseToken: claim.LeaseToken})
		}
		r, err := s.lookup(ctx, ip.String())
		if err != nil {
			release()
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			return Result{}, err
		}
		if err := ctx.Err(); err != nil {
			release()
			return Result{}, err
		}
		// Database time anchors persisted lifetimes consistently across service
		// processes. Preserve any longer registry Retry-After deadline.
		r.QueriedAt = claim.ClaimedAt.Time.UTC()
		ttl := time.Hour
		if r.LookupSucceeded {
			ttl = 24 * time.Hour
		}
		r.ExpiresAt = r.QueriedAt.Add(ttl)
		if r.RetryAfter.After(r.ExpiresAt) {
			r.ExpiresAt = r.RetryAfter
		}
		data, err = json.Marshal(r)
		if err != nil {
			release()
			return Result{}, errCacheInvalid
		}
		written, err := q.CompleteEnrichment(ctx, db.CompleteEnrichmentParams{Address: ip, LeaseToken: claim.LeaseToken, Result: data, QueriedAt: pgtype.Timestamptz{Time: r.QueriedAt, Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: r.ExpiresAt, Valid: true}})
		if err != nil {
			release()
			return Result{}, cacheError(ctx)
		}
		if written == 1 {
			return r, nil
		}
		// Our lease expired. Re-read/wait for the current owner; never return stale
		// in-memory evidence as though it were the successfully published result.
	}
}
func cacheError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errCache
}
