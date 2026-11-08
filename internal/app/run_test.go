package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"cheesetrap/internal/config"
)

func lookup(values map[string]string) config.LookupEnv {
	return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
}
func environment() map[string]string {
	return map[string]string{"CHEESETRAP_DATABASE_URL": "postgresql://app:canary-db-secret@db.invalid/cheesetrap"}
}
func TestInvalidConfigurationDoesNotDispatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		args   []string
		values map[string]string
	}{
		{"invalid command", []string{"canary-unknown-mode"}, environment()},
		{"missing database", []string{"api"}, nil},
		{"public management", []string{"api"}, map[string]string{"CHEESETRAP_DATABASE_URL": environment()["CHEESETRAP_DATABASE_URL"], "CHEESETRAP_API_LISTEN": "0.0.0.0:8080"}},
		{"SMTP on API", []string{"api"}, map[string]string{"CHEESETRAP_DATABASE_URL": environment()["CHEESETRAP_DATABASE_URL"], "CHEESETRAP_SMTP_SECRET_FILE": "/canary-secret-path"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			handler := func(context.Context, config.Config) error { calls++; return nil }
			var output bytes.Buffer
			got := Run(context.Background(), test.args, lookup(test.values), &output, Handlers{API: handler, Collector: handler, Worker: handler, Migrate: handler, AdminCreate: handler})
			if got != 2 {
				t.Errorf("exit = %d, want 2", got)
			}
			if calls != 0 {
				t.Error("invalid configuration dispatched a handler")
			}
			assertSafeJSON(t, output.String())
		})
	}
}
func TestDispatchesOnlySelectedRole(t *testing.T) {
	for _, test := range []struct {
		args []string
		role config.Role
	}{
		{[]string{"api"}, config.API}, {[]string{"collector"}, config.Collector}, {[]string{"worker"}, config.Worker},
		{[]string{"migrate"}, config.Migrate}, {[]string{"admin", "create"}, config.Admin},
	} {
		t.Run(string(test.role), func(t *testing.T) {
			values := environment()
			if test.role == config.Collector {
				values["CHEESETRAP_COLLECTOR_LOG_DIR"] = "/does-not-exist/logs"
				values["CHEESETRAP_COLLECTOR_SOURCES_FILE"] = "/config/sources.json"
			}
			var calls []config.Role
			handler := func(role config.Role) Handler {
				return func(_ context.Context, cfg config.Config) error {
					calls = append(calls, role)
					if cfg.Role != role || cfg.DatabaseURL != values["CHEESETRAP_DATABASE_URL"] {
						t.Error("handler received wrong configuration")
					}
					return nil
				}
			}
			var output bytes.Buffer
			got := Run(context.Background(), test.args, lookup(values), &output, Handlers{API: handler(config.API), Collector: handler(config.Collector), Worker: handler(config.Worker), Migrate: handler(config.Migrate), AdminCreate: handler(config.Admin)})
			if got != 0 || len(calls) != 1 || calls[0] != test.role {
				t.Errorf("exit = %d, calls = %v", got, calls)
			}
			assertSafeJSON(t, output.String())
		})
	}
}
func TestUnimplementedRolesFailWithoutReady(t *testing.T) {
	for _, args := range [][]string{{"api"}, {"collector"}, {"worker"}, {"migrate"}, {"admin", "create"}} {
		values := environment()
		if args[0] == "collector" {
			values["CHEESETRAP_COLLECTOR_LOG_DIR"] = "/does-not-exist/logs"
			values["CHEESETRAP_COLLECTOR_SOURCES_FILE"] = "/config/sources.json"
		}
		var output bytes.Buffer
		got := Run(context.Background(), args, lookup(values), &output, Handlers{})
		if got != 3 {
			t.Errorf("%v exit = %d, want 3", args, got)
		}
		if !strings.Contains(output.String(), "not_implemented") || strings.Contains(output.String(), "ready") || strings.Contains(output.String(), "role_started") {
			t.Errorf("misleading unimplemented output: %s", output.String())
		}
		assertSafeJSON(t, output.String())
	}
}
func TestRuntimeErrorsDoNotLeakSecrets(t *testing.T) {
	var output bytes.Buffer
	got := Run(context.Background(), []string{"worker"}, lookup(environment()), &output, Handlers{Worker: func(context.Context, config.Config) error {
		return errors.New("canary-handler-error contains postgresql://password and /smtp-secret")
	}})
	if got != 1 {
		t.Errorf("exit = %d, want 1", got)
	}
	if !strings.Contains(output.String(), "runtime_failure") {
		t.Error("missing stable failure code")
	}
	assertSafeJSON(t, output.String())
}
func TestHelpExplainsRolesWithoutConfig(t *testing.T) {
	var output bytes.Buffer
	got := Run(context.Background(), []string{"--help"}, func(string) (string, bool) { t.Error("help read config"); return "", false }, &output, Handlers{})
	if got != 0 {
		t.Errorf("exit = %d", got)
	}
	for _, text := range []string{"admin create", "durable detection/window queues", "CHEESETRAP_DATABASE_URL", "CHEESETRAP_SHUTDOWN_GRACE", "CHEESETRAP_API_LISTEN", "CHEESETRAP_COLLECTOR_LOG_DIR"} {
		if !strings.Contains(output.String(), text) {
			t.Errorf("help missing %q", text)
		}
	}
}
func TestCancelledContextDoesNotStartHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	got := Run(ctx, []string{"worker"}, lookup(environment()), io.Discard, Handlers{Worker: func(context.Context, config.Config) error { called = true; return nil }})
	if got != 0 || called {
		t.Errorf("exit = %d, called = %v", got, called)
	}
}
func TestCancellationWaitsForHandlerCompletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, stopping, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(release)
	finished := make(chan int, 1)
	go func() {
		finished <- Run(ctx, []string{"worker"}, lookup(environment()), io.Discard, Handlers{Worker: func(ctx context.Context, _ config.Config) error {
			close(started)
			<-ctx.Done()
			close(stopping)
			<-release
			return ctx.Err()
		}})
	}()
	waitStarted(t, started, finished)
	cancel()
	select {
	case <-stopping:
	case code := <-finished:
		t.Fatalf("returned %d before handler observed cancellation", code)
	case <-time.After(time.Second):
		t.Fatal("cancellation was not delivered")
	}
	select {
	case code := <-finished:
		t.Fatalf("returned %d while handler was still stopping", code)
	case <-time.After(20 * time.Millisecond):
	}
	// Closing release is deferred so the pending handler cannot be leaked by a failure.
	release <- struct{}{}
	if got := waitExit(t, finished); got != 0 {
		t.Errorf("graceful exit = %d, want 0", got)
	}
}
func TestShutdownTimeoutIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, release, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	invoked := false
	defer func() {
		close(release)
		if invoked {
			select {
			case <-handlerDone:
			case <-time.After(time.Second):
				t.Error("handler did not finish after release")
			}
		}
	}()
	values := environment()
	values["CHEESETRAP_SHUTDOWN_GRACE"] = "10ms"
	finished := make(chan int, 1)
	go func() {
		finished <- Run(ctx, []string{"worker"}, lookup(values), io.Discard, Handlers{Worker: func(context.Context, config.Config) error {
			defer close(handlerDone)
			close(started)
			<-release
			return nil
		}})
	}()
	// Do not wait for a handler that never started.
	select {
	case <-started:
		invoked = true
	case got := <-finished:
		t.Fatalf("runner returned %d before starting handler", got)
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	if got := waitExit(t, finished); got != 1 {
		t.Errorf("timeout exit = %d, want 1", got)
	}
}
func TestGracePeriodStartsOnlyAfterCancellation(t *testing.T) {
	values := environment()
	values["CHEESETRAP_SHUTDOWN_GRACE"] = "1ns"
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	finished := make(chan int, 1)
	go func() {
		finished <- Run(context.Background(), []string{"worker"}, lookup(values), io.Discard, Handlers{Worker: func(context.Context, config.Config) error {
			close(started)
			<-release
			return nil
		}})
	}()
	waitStarted(t, started, finished)
	select {
	case got := <-finished:
		t.Fatalf("grace timer ended healthy handler with exit %d", got)
	case <-time.After(20 * time.Millisecond):
	}
	release <- struct{}{}
	if got := waitExit(t, finished); got != 0 {
		t.Errorf("exit = %d", got)
	}
}
func TestCancellationDoesNotHideRuntimeFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	finished := make(chan int, 1)
	go func() {
		finished <- Run(ctx, []string{"worker"}, lookup(environment()), io.Discard, Handlers{Worker: func(ctx context.Context, _ config.Config) error {
			close(started)
			<-ctx.Done()
			return errors.New("canary-failure-during-shutdown")
		}})
	}()
	waitStarted(t, started, finished)
	cancel()
	if got := waitExit(t, finished); got != 1 {
		t.Errorf("exit = %d, want runtime failure", got)
	}
}
func TestCancellationErrorPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		result func(error) error
		exit   int
	}{
		{"nil after cleanup", func(error) error { return nil }, 0},
		{"exact context error", func(err error) error { return err }, 0},
		{"wrapped context error", func(err error) error { return fmt.Errorf("canary-shutdown-detail: %w", err) }, 1},
		{"joined cleanup failure", func(err error) error { return errors.Join(err, errors.New("canary-cleanup-failure")) }, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			finished := make(chan int, 1)
			var output bytes.Buffer
			go func() {
				finished <- Run(ctx, []string{"worker"}, lookup(environment()), &output, Handlers{Worker: func(ctx context.Context, _ config.Config) error {
					close(started)
					<-ctx.Done()
					return test.result(ctx.Err())
				}})
			}()
			waitStarted(t, started, finished)
			cancel()
			if got := waitExit(t, finished); got != test.exit {
				t.Errorf("exit = %d, want %d", got, test.exit)
			}
			assertSafeJSON(t, output.String())
		})
	}
}

func waitStarted(t *testing.T, started <-chan struct{}, finished <-chan int) {
	t.Helper()
	select {
	case <-started:
	case got := <-finished:
		t.Fatalf("runner returned %d before starting handler", got)
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
}
func waitExit(t *testing.T, finished <-chan int) int {
	t.Helper()
	select {
	case got := <-finished:
		return got
	case <-time.After(time.Second):
		t.Fatal("runner did not return within one second")
		return -1
	}
}
func assertSafeJSON(t *testing.T, output string) {
	t.Helper()
	if strings.Contains(output, "canary") || strings.Contains(output, "postgresql://") || strings.Contains(output, "/smtp-secret") {
		t.Error("output leaked a secret or raw input")
	}
	decoder := json.NewDecoder(strings.NewReader(output))
	records := 0
	for {
		var record map[string]any
		err := decoder.Decode(&record)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("output is not JSON: %v", err)
		}
		for key := range record {
			switch key {
			case "time", "level", "msg", "role", "error_code":
			default:
				t.Errorf("unapproved log field: %s", key)
			}
		}
		records++
	}
	if records == 0 {
		t.Error("expected a structured log record")
	}
}
