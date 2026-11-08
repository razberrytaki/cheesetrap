package api

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"cheesetrap/internal/store"
)

// Run binds the already-validated loopback address and owns all resources.
func Run(ctx context.Context, databaseURL, address, origin string, grace time.Duration) error {
	pool, err := store.NewPool(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.New("api_listen_failed")
	}
	server := &http.Server{Handler: NewHandler(pool, origin), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 * 1024, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("api_serve_failed")
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), grace*9/10)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			<-done
			return errors.New("api_shutdown_failed")
		}
		<-done
		return ctx.Err()
	}
}
