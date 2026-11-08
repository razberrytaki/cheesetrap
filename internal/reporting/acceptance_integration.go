//go:build integration

package reporting

import (
	"cheesetrap/internal/enrichment"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewAcceptanceDraftService is test-build-only; normal construction always fixes
// the production resolver and cannot accept a transport override.
func NewAcceptanceDraftService(pool *pgxpool.Pool, lookup interface {
	Lookup(context.Context, string) (enrichment.Result, error)
}) *DraftService {
	return &DraftService{pool: pool, contacts: lookup}
}
