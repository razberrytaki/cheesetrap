// Package app validates configuration and runs exactly one selected role.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"cheesetrap/internal/config"
)

const (
	ExitSuccess        = 0
	ExitRuntime        = 1
	ExitConfiguration  = 2
	ExitNotImplemented = 3
)

const usage = `Usage: cheesetrap api | collector | worker | migrate | admin create
       cheesetrap api-schema --out api/openapi.json
       cheesetrap help | -h | --help

Migrate applies embedded PostgreSQL migrations with a separate migration account.
Collector tails configured sources and atomically commits evidence/checkpoints.
Worker runs durable detection/window queues, drafting and contact refresh. Cheesetrap never sends email.
Admin create prompts locally with hidden password, or reads username LF password [LF] from stdin.
Passwords are 12–1024 bytes. Use a protected input file for noninteractive creation.
API schema generation is local and does not require a database or listener.
Configuration parsing does not connect to PostgreSQL, bind a listener, or read files.

Environment (empty means unset):
  CHEESETRAP_DATABASE_URL       Hosted postgres/postgresql URL with database name.
  CHEESETRAP_DATABASE_URL_FILE  Alternative private regular file (max 4096 bytes); exactly one URL source.
  CHEESETRAP_API_CONTAINER_LISTENER API only: true permits 0.0.0.0 with explicit loopback API_ORIGIN.
  CHEESETRAP_SHUTDOWN_GRACE     Positive duration up to 5m; default 10s.
  CHEESETRAP_API_LISTEN         API only: literal loopback IP:port; default 127.0.0.1:8080.
  CHEESETRAP_API_ORIGIN         API only: exact loopback HTTP browser origin; defaults from API_LISTEN.
                              Port 80 is omitted (http://127.0.0.1); IPv4-mapped IPv6 is unsupported.
  CHEESETRAP_COLLECTOR_LOG_DIR  Collector only: required absolute sensor log directory.
  CHEESETRAP_COLLECTOR_SOURCES_FILE Collector only: required absolute JSON manifest outside log directory.
Nonempty role-specific variables are forbidden for other roles.

Exit codes: 0 success/help/graceful completion, 1 runtime failure/shutdown timeout,
            2 usage/configuration error, 3 not implemented.
`

// Handler must finish its cleanup before returning after context cancellation.
// Successful cancellation returns nil or exactly ctx.Err(); wrapped or joined
// errors are failures, so independent cleanup errors cannot be hidden.
// File/network I/O belongs inside the selected handler, after validation.
type Handler func(context.Context, config.Config) error

// Handlers is the explicit dispatch boundary for subsequent milestones. A nil
// handler is unimplemented, never a successful empty daemon or a ready service.
type Handlers struct {
	API         Handler
	APISchema   Handler
	Collector   Handler
	Worker      Handler
	Migrate     Handler
	AdminCreate Handler
}

// Run validates before dispatch, logs only static event/error codes and the
// validated role, and returns a process exit code. It bounds shutdown after
// cancellation, not normal runtime. A timed-out handler cannot be killed here;
// the command must exit the process with the returned failure code.
func Run(ctx context.Context, args []string, lookup config.LookupEnv, output io.Writer, handlers Handlers) int {
	logger := slog.New(slog.NewJSONHandler(output, nil))
	cfg, err := config.Parse(args, lookup)
	if errors.Is(err, config.ErrHelp) {
		fmt.Fprint(output, usage)
		return ExitSuccess
	}
	if err != nil {
		// Parse returns only predefined configuration errors, never raw inputs.
		logger.Error("configuration_rejected", "error_code", err.Error())
		return ExitConfiguration
	}
	logger = logger.With("role", string(cfg.Role))
	var handler Handler
	switch cfg.Role {
	case config.API:
		handler = handlers.API
	case config.APISchema:
		handler = handlers.APISchema
	case config.Collector:
		handler = handlers.Collector
	case config.Worker:
		handler = handlers.Worker
	case config.Migrate:
		handler = handlers.Migrate
	case config.Admin:
		handler = handlers.AdminCreate
	}
	if handler == nil {
		logger.Error("role_unavailable", "error_code", "not_implemented")
		return ExitNotImplemented
	}
	if ctx.Err() != nil {
		logger.Info("cancelled_before_start")
		return ExitSuccess
	}
	if cfg.DatabaseURLFile != "" && cfg.Role != config.APISchema {
		url, err := readDatabaseURL(cfg.DatabaseURLFile)
		if err != nil {
			logger.Error("configuration_rejected", "error_code", "database_url_file_invalid")
			return ExitConfiguration
		}
		cfg.DatabaseURL = url
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	completed := make(chan error, 1)
	logger.Info("role_started")
	go func() { completed <- handler(runCtx, cfg) }()
	select {
	case err := <-completed:
		return completedExit(ctx, err, logger)
	case <-ctx.Done():
		logger.Info("shutdown_requested")
		timer := time.NewTimer(cfg.ShutdownGrace)
		defer timer.Stop()
		select {
		case err := <-completed:
			return completedExit(ctx, err, logger)
		case <-timer.C:
			logger.Error("shutdown_failed", "error_code", "shutdown_timeout")
			return ExitRuntime
		}
	}
}

func completedExit(ctx context.Context, err error, logger *slog.Logger) int {
	if err != nil && !(ctx.Err() != nil && err == ctx.Err()) {
		logger.Error("role_failed", "error_code", "runtime_failure")
		return ExitRuntime
	}
	logger.Info("role_completed")
	return ExitSuccess
}

// Credential loading occurs only after pure role validation and dispatch selection.
// Symlinks, non-private permissions and unbounded inputs are never accepted.
func readDatabaseURL(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return "", config.ErrDatabaseURLFileInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return "", config.ErrDatabaseURLFileInvalid
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", config.ErrDatabaseURLFileInvalid
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	value := strings.TrimSuffix(string(data), "\n")
	if err != nil || len(data) > 4096 || !config.ValidDatabaseURL(value) || strings.ContainsAny(value, "\r\n") {
		return "", config.ErrDatabaseURLFileInvalid
	}
	return value, nil
}
