package app

import (
	"context"
	"os"

	"cheesetrap/internal/api"
	"cheesetrap/internal/auth"
	"cheesetrap/internal/config"
	"cheesetrap/internal/ingestion"
	"cheesetrap/internal/jobs"
	"cheesetrap/internal/store"
)

// ProductionHandlers wires each role to its implemented runtime.
func ProductionHandlers() Handlers {
	return Handlers{API: func(ctx context.Context, cfg config.Config) error {
		return api.Run(ctx, cfg.DatabaseURL, cfg.APIListen, cfg.APIOrigin, cfg.ShutdownGrace)
	}, APISchema: func(_ context.Context, cfg config.Config) error {
		data, err := api.Schema()
		if err != nil {
			return err
		}
		return os.WriteFile(cfg.SchemaOutput, append(data, '\n'), 0644)
	}, AdminCreate: func(ctx context.Context, cfg config.Config) error {
		username, password, err := auth.ReadAdminInput(ctx, os.Stdin, os.Stderr)
		if err != nil {
			return err
		}
		pool, err := store.NewPool(ctx, cfg.DatabaseURL)
		if err != nil {
			return err
		}
		defer pool.Close()
		return auth.NewService(pool).CreateAdmin(ctx, username, password)
	}, Collector: func(ctx context.Context, cfg config.Config) error {
		return ingestion.RunCollector(ctx, cfg.DatabaseURL, cfg.CollectorLogDir, cfg.CollectorSourcesFile)
	}, Worker: func(ctx context.Context, cfg config.Config) error {
		return jobs.Run(ctx, cfg.DatabaseURL, cfg.ShutdownGrace)
	}, Migrate: func(ctx context.Context, cfg config.Config) error {
		return store.Migrate(ctx, cfg.DatabaseURL)
	}}
}
