package app

import (
	"bytes"
	"cheesetrap/internal/config"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallDatabaseSecretFile(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		mode          os.FileMode
		ok            bool
	}{
		{"valid", "postgresql://api:private-canary@db/cheesetrap\n", 0600, true},
		{"invalid", "private-canary", 0600, false}, {"large", strings.Repeat("private-canary", 1000), 0600, false},
		{"permissions", "postgresql://api:private-canary@db/cheesetrap", 0644, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dsn")
			if os.WriteFile(path, []byte(tc.content), tc.mode) != nil {
				t.Fatal("write fixture")
			}
			if os.Chmod(path, tc.mode) != nil {
				t.Fatal("fixture chmod")
			}
			var output bytes.Buffer
			called := false
			code := Run(context.Background(), []string{"migrate"}, func(k string) (string, bool) {
				if k == "CHEESETRAP_DATABASE_URL_FILE" {
					return path, true
				}
				return "", false
			}, &output, Handlers{Migrate: func(_ context.Context, c config.Config) error {
				called = true
				if c.DatabaseURL != "postgresql://api:private-canary@db/cheesetrap" {
					t.Error("wrong loaded DSN")
				}
				return nil
			}})
			if (code == 0) != tc.ok || called != tc.ok {
				t.Errorf("code=%d called=%v", code, called)
			}
			if strings.Contains(output.String(), "private-canary") {
				t.Fatal("secret leaked")
			}
		})
	}
}

func TestInstallSchemaIgnoresAmbientDatabaseSecretFile(t *testing.T) {
	var output bytes.Buffer
	called := false
	code := Run(context.Background(), []string{"api-schema", "--out", "schema.json"}, func(key string) (string, bool) {
		if key == "CHEESETRAP_DATABASE_URL_FILE" {
			return "/never/read/ambient-secret", true
		}
		return "", false
	}, &output, Handlers{APISchema: func(context.Context, config.Config) error { called = true; return nil }})
	if code != 0 || !called {
		t.Fatalf("pure schema attempted credential loading: code=%d called=%v", code, called)
	}
}
