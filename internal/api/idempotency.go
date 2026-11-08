package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"cheesetrap/internal/auth"
	"cheesetrap/internal/reporting"
	"cheesetrap/internal/store/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func reviewUUID(s string) pgtype.UUID { var id pgtype.UUID; _ = id.Scan(s); return id }
func validKey(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

// Only successful commands are committed. A transaction advisory lock serializes
// a principal's key even before its first row exists. Replay precedes optimistic
// checks; request identity includes method, resource and normalized typed input.
func idempotent[T any](ctx context.Context, s *server, key, method, resource string, input any, status int, command func(pgx.Tx) (T, error)) (T, error) {
	var zero T
	if !validKey(key) {
		return zero, apiError(400)
	}
	actor, ok := ctx.Value(identityKey).(auth.Identity)
	if !ok {
		return zero, apiError(401)
	}
	data, err := json.Marshal(struct {
		Method, Resource string
		Input            any
	}{method, resource, input})
	if err != nil {
		return zero, apiError(400)
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return zero, apiError(503)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, actor.AdminID+":"+key); err != nil {
		return zero, apiError(503)
	}
	q := db.New(tx)
	prior, err := q.GetReviewIdempotency(ctx, db.GetReviewIdempotencyParams{AdminID: reviewUUID(actor.AdminID), Key: key})
	if err == nil {
		if prior.RequestHash != hash || int(prior.Status) != status {
			return zero, apiError(409)
		}
		var result T
		if json.Unmarshal(prior.Response, &result) != nil {
			return zero, apiError(503)
		}
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return zero, apiError(503)
	}
	result, err := command(tx)
	if err != nil {
		return zero, reviewError(err)
	}
	data, err = json.Marshal(result)
	if err != nil {
		return zero, apiError(503)
	}
	if err = q.SaveReviewIdempotency(ctx, db.SaveReviewIdempotencyParams{AdminID: reviewUUID(actor.AdminID), Key: key, RequestHash: hash, Status: int32(status), Response: data}); err != nil {
		return zero, apiError(503)
	}
	if err = tx.Commit(ctx); err != nil {
		return zero, apiError(503)
	}
	return result, nil
}
func reviewAudit(ctx context.Context, tx pgx.Tx, action string, details any) error {
	actor, ok := ctx.Value(identityKey).(auth.Identity)
	if !ok {
		return apiError(401)
	}
	data, err := json.Marshal(details)
	if err != nil {
		return apiError(503)
	}
	return db.New(tx).AppendReviewAudit(ctx, db.AppendReviewAuditParams{AdminID: reviewUUID(actor.AdminID), Action: action, Details: data})
}
func reviewError(err error) error {
	var api *Error
	if errors.As(err, &api) {
		return api
	}
	switch {
	case errors.Is(err, reporting.ErrRevisionConflict):
		return apiError(409)
	case errors.Is(err, reporting.ErrRevisionInput), errors.Is(err, reporting.ErrSchedule):
		return apiError(400)
	case errors.Is(err, pgx.ErrNoRows):
		return apiError(404)
	default:
		return apiError(503)
	}
}
