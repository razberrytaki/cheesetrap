// Package store owns database connections and application schema migrations.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrDatabaseConfiguration = errors.New("database_configuration_invalid")
	ErrDatabaseConnection    = errors.New("database_connection_failed")
	ErrMigration             = errors.New("database_migration_failed")
)

// NewPool establishes and pings a bounded pool. The caller owns Close. Driver
// errors contain credentials/SQL details and must not cross this boundary.
// TLS follows the supplied DSN; this function never disables it globally.
func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, ErrDatabaseConfiguration
	}
	cfg.MaxConns = 4
	cfg.MinConns = 0
	cfg.MinIdleConns = 0
	cfg.MaxConnLifetimeJitter = 0
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = time.Minute
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	cfg.ConnConfig.RuntimeParams["search_path"] = "pg_catalog,cheesetrap"
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "30000"
	cfg.ConnConfig.RuntimeParams["lock_timeout"] = "10000"
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "30000"
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(connectCtx, cfg)
	if err == nil {
		err = pool.Ping(connectCtx)
	}
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrDatabaseConnection
	}
	return pool, nil
}
