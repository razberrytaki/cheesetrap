package store

import (
	"context"
	"io"
	"log/slog"
	"time"

	"cheesetrap/migrations"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

// Migrate uses one independent Goose provider and an advisory session lock.
// It never uses Goose global state. The migration role/schema must already be
// provisioned; this command cannot bootstrap elevated roles or databases.
func Migrate(ctx context.Context, databaseURL string) error {
	migrationCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	pool, err := NewPool(migrationCtx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	// Serialize the complete Goose + River history across independent migrators.
	// The lock lives on a dedicated session, not a transaction spanning history.
	session, err := pool.Acquire(migrationCtx)
	if err != nil {
		return ErrMigration
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = session.Hijack().Close(closeCtx) // closing also releases an interrupted lock
	}()
	if _, err = session.Exec(migrationCtx, "SELECT pg_advisory_lock(7142178613021)"); err != nil {
		return ErrMigration
	}

	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockTimeout(1, 30), lock.WithUnlockTimeout(1, 3))
	if err != nil {
		return ErrMigration
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files,
		goose.WithTableName("cheesetrap.goose_db_version"),
		goose.WithSessionLocker(locker), goose.WithDisableGlobalRegistry(true),
		goose.WithSlog(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		return ErrMigration
	}
	// provider.Close owns the SQL facade; the underlying pgx pool closes after it.
	defer provider.Close()
	if _, err = provider.Up(migrationCtx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrMigration
	}
	riverMigrator, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Schema: "cheesetrap_river", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		return ErrMigration
	}
	// Official Migrate commits each migration independently, required by enum DDL.
	if _, err = riverMigrator.Migrate(migrationCtx, rivermigrate.DirectionUp, &rivermigrate.MigrateOpts{TargetVersion: 8}); err != nil {
		return ErrMigration
	}
	_, err = pool.Exec(migrationCtx, `REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
 GRANT USAGE ON SCHEMA cheesetrap_river TO cheesetrap_worker,cheesetrap_api;
 GRANT SELECT,INSERT ON cheesetrap_river.river_job TO cheesetrap_api;
 GRANT UPDATE(kind) ON cheesetrap_river.river_job TO cheesetrap_api;
 GRANT USAGE ON SEQUENCE cheesetrap_river.river_job_id_seq TO cheesetrap_api;
 GRANT EXECUTE ON FUNCTION cheesetrap_river.river_job_state_in_bitmask(bit,cheesetrap_river.river_job_state) TO cheesetrap_api;
 GRANT SELECT,INSERT,UPDATE,DELETE ON cheesetrap_river.river_job,cheesetrap_river.river_queue,cheesetrap_river.river_leader,cheesetrap_river.river_notification TO cheesetrap_worker;
 GRANT USAGE ON SEQUENCE cheesetrap_river.river_job_id_seq,cheesetrap_river.river_notification_id_seq TO cheesetrap_worker;
 GRANT EXECUTE ON FUNCTION cheesetrap_river.river_job_state_in_bitmask(bit,cheesetrap_river.river_job_state) TO cheesetrap_worker;`)
	if err != nil {
		return ErrMigration
	}
	return nil
}
