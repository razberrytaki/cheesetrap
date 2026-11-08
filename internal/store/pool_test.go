package store

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPoolRejectsMalformedConfiguration(t *testing.T) {
	pool, err := NewPool(context.Background(), "postgres://user:canary-secret@127.0.0.1/db?pool_max_conns=broken")
	if pool != nil {
		pool.Close()
		t.Fatal("invalid config returned a pool")
	}
	if err == nil || strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), "postgres://") {
		t.Fatal("invalid config must return a sanitized error")
	}
}

func TestPoolConnectionFailureIsBounded(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("local test listener failed")
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal("local test listener close failed")
	}
	start := time.Now()
	pool, err := NewPool(context.Background(), "postgres://user:canary-secret@"+address+"/db?sslmode=disable")
	if pool != nil {
		pool.Close()
		t.Fatal("unavailable server returned a pool")
	}
	if err == nil || strings.Contains(err.Error(), "canary") || time.Since(start) > 6*time.Second {
		t.Fatal("connection failure must be bounded and sanitized")
	}
}

func TestPoolCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pool, err := NewPool(ctx, "postgres://user:canary-secret@127.0.0.1:1/db?sslmode=disable")
	if pool != nil {
		pool.Close()
		t.Fatal("cancelled connection returned a pool")
	}
	if err != context.Canceled {
		t.Fatal("connection must preserve caller cancellation")
	}
	if err := Migrate(ctx, "postgres://user:canary-secret@127.0.0.1:1/db?sslmode=disable"); err != context.Canceled {
		t.Fatal("migration must preserve caller cancellation")
	}
}
