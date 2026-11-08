package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Build and run the actual command so os.Exit behavior is tested, not only Run's
// return value. Each process gets only explicit synthetic configuration.
func TestCLIExitCodes(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "cheesetrap")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build command: %v\n%s", err, output)
	}
	database := "CHEESETRAP_DATABASE_URL=postgresql://app:canary-db-secret@db.invalid/cheesetrap"
	for _, test := range []struct {
		name      string
		args, env []string
		exit      int
		code      string
	}{
		{"help", []string{"--help"}, nil, 0, ""},
		{"invalid command", []string{"canary-invalid-command"}, nil, 2, "invalid_command"},
		{"missing config", []string{"api"}, nil, 2, "database_url_required"},
		{"public bind", []string{"api"}, []string{database, "CHEESETRAP_API_LISTEN=0.0.0.0:8080"}, 2, "api_listen_invalid"},
		{"removed SMTP option", []string{"api"}, []string{database, "CHEESETRAP_SMTP_SECRET_FILE=/canary-secret-path"}, 2, "smtp_configuration_removed"},
		{"api connection failure", []string{"api"}, []string{"CHEESETRAP_DATABASE_URL=postgresql://app:canary@127.0.0.1:1/cheesetrap?sslmode=disable"}, 1, "runtime_failure"},
		{"collector missing sources", []string{"collector"}, []string{database, "CHEESETRAP_COLLECTOR_LOG_DIR=/does-not-exist/logs"}, 2, "collector_sources_file_invalid"},
		{"worker connection failure", []string{"worker"}, []string{"CHEESETRAP_DATABASE_URL=postgresql://worker:canary@127.0.0.1:1/cheesetrap?sslmode=disable"}, 1, "runtime_failure"},
		{"migrate invalid config", []string{"migrate"}, []string{"CHEESETRAP_DATABASE_URL=canary-invalid"}, 2, "database_url_invalid"},
		{"admin missing input", []string{"admin", "create"}, []string{database}, 1, "runtime_failure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, test.args...)
			command.Env = append([]string{}, test.env...)
			output, err := command.CombinedOutput()
			exit := 0
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("run command: %v", err)
				}
				exit = exitErr.ExitCode()
			}
			if exit != test.exit {
				t.Errorf("exit = %d, want %d", exit, test.exit)
			}
			if strings.Contains(string(output), "canary") || strings.Contains(string(output), "ready") {
				t.Error("CLI leaked input or claimed readiness")
			}
			if test.code == "" {
				if !strings.Contains(string(output), "durable detection/window queues") {
					t.Error("help did not explain worker scope")
				}
				return
			}
			var record map[string]any
			decoder := json.NewDecoder(bytes.NewReader(output))
			for {
				var next map[string]any
				err := decoder.Decode(&next)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal("expected structured runtime records")
				}
				record = next
			}
			if record["error_code"] != test.code {
				t.Errorf("error code = %v, want %s", record["error_code"], test.code)
			}
		})
	}
}
