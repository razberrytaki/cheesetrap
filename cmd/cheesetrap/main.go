package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"cheesetrap/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := app.Run(ctx, os.Args[1:], os.LookupEnv, os.Stderr, app.ProductionHandlers())
	stop()
	os.Exit(code)
}
