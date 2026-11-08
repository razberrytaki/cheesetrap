package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func env(values map[string]string) LookupEnv {
	return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
}

func validEnv() map[string]string {
	return map[string]string{"CHEESETRAP_DATABASE_URL": "postgresql://app:canary-db-password@db.invalid/cheesetrap"}
}

func TestInvalidCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown-canary"}, {"admin"}, {"admin", "delete"}, {"api", "extra"}, {"admin", "create", "extra"}, {"--help", "extra"}} {
		if _, err := Parse(args, env(validEnv())); !errors.Is(err, ErrInvalidCommand) {
			t.Errorf("Parse(%q) error = %v, want invalid command", args, err)
		}
	}
}

func TestMissingDatabaseConfiguration(t *testing.T) {
	for _, args := range [][]string{{"api"}, {"collector"}, {"worker"}, {"migrate"}, {"admin", "create"}} {
		if _, err := Parse(args, env(nil)); !errors.Is(err, ErrDatabaseURLRequired) {
			t.Errorf("Parse(%q) error = %v, want missing database URL", args, err)
		}
	}
}

func TestRejectsPublicOrAmbiguousManagementBind(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8080", ":8080", "[::]:8080", "192.0.2.1:8080", "[2001:db8::1]:8080", "localhost:8080", "127.0.0.1", "127.0.0.1:http", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:-1", "[::1%lo0]:8080"} {
		values := validEnv()
		values["CHEESETRAP_API_LISTEN"] = address
		if _, err := Parse([]string{"api"}, env(values)); !errors.Is(err, ErrAPIListenInvalid) {
			t.Errorf("address %q error = %v, want invalid loopback address", address, err)
		}
	}
}

func TestRejectsRemovedSMTPSecretForAllRoles(t *testing.T) {
	for _, args := range [][]string{{"api"}, {"collector"}, {"worker"}, {"migrate"}, {"admin", "create"}, {"api-schema", "--out", "schema.json"}} {
		values := validEnv()
		values["CHEESETRAP_SMTP_SECRET_FILE"] = "/never-read/canary-smtp-secret"
		if _, err := Parse(args, env(values)); !errors.Is(err, ErrRemovedSMTPOption) {
			t.Errorf("Parse(%q) error = %v, want forbidden role option", args, err)
		}
	}
}

func TestRoleOptionsCannotLeakIntoOtherRoles(t *testing.T) {
	for _, key := range []string{"CHEESETRAP_API_LISTEN", "CHEESETRAP_COLLECTOR_LOG_DIR"} {
		values := validEnv()
		values[key] = "canary-foreign-option"
		if _, err := Parse([]string{"worker"}, env(values)); !errors.Is(err, ErrRoleOption) {
			t.Errorf("key %s error = %v, want forbidden role option", key, err)
		}
	}
}

func TestValidRolesAndDefaults(t *testing.T) {
	for _, test := range []struct {
		args []string
		role Role
	}{
		{[]string{"api"}, API}, {[]string{"collector"}, Collector}, {[]string{"worker"}, Worker},
		{[]string{"migrate"}, Migrate}, {[]string{"admin", "create"}, Admin},
	} {
		values := validEnv()
		if test.role == Collector {
			values["CHEESETRAP_COLLECTOR_LOG_DIR"] = "/does-not-exist/sensor-logs"
			values["CHEESETRAP_COLLECTOR_SOURCES_FILE"] = "/config/sources.json"
		}
		cfg, err := Parse(test.args, env(values))
		if err != nil {
			t.Fatalf("%s: %v", test.role, err)
		}
		if cfg.Role != test.role || cfg.DatabaseURL != values["CHEESETRAP_DATABASE_URL"] || cfg.ShutdownGrace != 10*time.Second {
			t.Errorf("%s: wrong role, database URL, or default grace", test.role)
		}
		if test.role == API && cfg.APIListen != "127.0.0.1:8080" {
			t.Errorf("wrong default API address: %q", cfg.APIListen)
		}
		if test.role != API && cfg.APIListen != "" {
			t.Errorf("%s has API configuration", test.role)
		}
		if cfg.CollectorLogDir != values["CHEESETRAP_COLLECTOR_LOG_DIR"] {
			t.Errorf("%s: log directory not preserved", test.role)
		}
	}
}

func TestAcceptsExplicitLoopbackAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8081", "127.1.2.3:65535", "[::1]:8080"} {
		values := validEnv()
		values["CHEESETRAP_API_LISTEN"] = address
		cfg, err := Parse([]string{"api"}, env(values))
		if err != nil || cfg.APIListen != address {
			t.Errorf("address %q rejected or altered: %v", address, err)
		}
	}
}

func TestDatabaseURLValidationDoesNotEchoSecrets(t *testing.T) {
	for _, value := range []string{"canary-invalid-dsn", "mysql://user:canary@db.invalid/name", "postgresql:///name?password=canary", "postgresql://db.invalid", "postgresql://db.invalid/", "postgresql://db.invalid:0/name", "postgresql://db.invalid:65536/name", "postgresql://db.invalid/name#canary", "postgresql://user:canary%zz@db.invalid/name"} {
		values := validEnv()
		values["CHEESETRAP_DATABASE_URL"] = value
		_, err := Parse([]string{"api"}, env(values))
		if !errors.Is(err, ErrDatabaseURLInvalid) {
			t.Errorf("URL rejected incorrectly: %v", err)
		}
		if err != nil && strings.Contains(err.Error(), "canary") {
			t.Error("database error leaked input")
		}
	}
}

func TestShutdownGraceBounds(t *testing.T) {
	for _, value := range []string{"0s", "-1s", "5m1ns", "canary-invalid-duration", "99999999999999999999h"} {
		values := validEnv()
		values["CHEESETRAP_SHUTDOWN_GRACE"] = value
		if _, err := Parse([]string{"worker"}, env(values)); !errors.Is(err, ErrShutdownGraceInvalid) {
			t.Errorf("grace %q error = %v, want invalid shutdown grace", value, err)
		}
	}
	for _, value := range []string{"1ns", "250ms", "5m"} {
		values := validEnv()
		values["CHEESETRAP_SHUTDOWN_GRACE"] = value
		cfg, err := Parse([]string{"worker"}, env(values))
		want, _ := time.ParseDuration(value)
		if err != nil || cfg.ShutdownGrace != want {
			t.Errorf("valid grace %q not preserved: %v", value, err)
		}
	}
}

func TestCollectorRequiresAbsoluteLogDirectory(t *testing.T) {
	values := validEnv()
	if _, err := Parse([]string{"collector"}, env(values)); !errors.Is(err, ErrCollectorLogDirRequired) {
		t.Errorf("missing log directory: %v", err)
	}
	values["CHEESETRAP_COLLECTOR_LOG_DIR"] = "relative/logs"
	if _, err := Parse([]string{"collector"}, env(values)); !errors.Is(err, ErrCollectorLogDirInvalid) {
		t.Errorf("relative log directory: %v", err)
	}
}

func TestWorkerRejectsRemovedSMTPConfiguration(t *testing.T) {
	values := validEnv()
	values["CHEESETRAP_SMTP_TEST_RECIPIENT"] = "removed-canary"
	if _, err := Parse([]string{"worker"}, env(values)); !errors.Is(err, ErrRemovedSMTPOption) {
		t.Fatalf("removed recipient option accepted: %v", err)
	}
}

func TestHelpDoesNotReadConfiguration(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		_, err := Parse([]string{arg}, func(string) (string, bool) { t.Fatal("help read environment"); return "", false })
		if !errors.Is(err, ErrHelp) {
			t.Errorf("%s error = %v, want help", arg, err)
		}
	}
}

func TestCollectorRequiresExternalSourcesFile(t *testing.T) {
	for _, path := range []string{"", "relative.json", "/logs/sources.json", "/logs/../logs/sources.json"} {
		values := validEnv()
		values["CHEESETRAP_COLLECTOR_LOG_DIR"] = "/logs"
		values["CHEESETRAP_COLLECTOR_SOURCES_FILE"] = path
		if _, err := Parse([]string{"collector"}, env(values)); err == nil {
			t.Fatal("unsafe/missing collector source manifest accepted")
		}
	}
	values := validEnv()
	values["CHEESETRAP_COLLECTOR_SOURCES_FILE"] = "/config/sources.json"
	if _, err := Parse([]string{"api"}, env(values)); !errors.Is(err, ErrRoleOption) {
		t.Fatal("collector source option escaped role boundary")
	}
}

func TestAPIOriginAndPureSchema(t *testing.T) {
	for _, origin := range []string{"http://evil.invalid:8080", "http://127.0.0.1:8080/", "http://127.0.0.1:8080?x=y", "http://u:p@127.0.0.1:8080", "http://127.0.0.1:0", "http://127.0.0.1:8080#x"} {
		values := validEnv()
		values["CHEESETRAP_API_ORIGIN"] = origin
		if _, err := Parse([]string{"api"}, env(values)); err == nil {
			t.Errorf("invalid origin accepted: %s", origin)
		}
	}
	values := validEnv()
	values["CHEESETRAP_API_ORIGIN"] = "http://127.0.0.1:9000"
	if _, err := Parse([]string{"api"}, env(values)); err != nil {
		t.Fatal("forwarded client origin rejected")
	}
	if _, err := Parse([]string{"worker"}, env(values)); err == nil {
		t.Fatal("foreign origin role option accepted")
	}
	if _, err := Parse([]string{"api-schema", "--out", "api/openapi.json"}, env(nil)); err != nil {
		t.Fatal("pure schema command requires database or is missing")
	}
}

func TestAPIOriginBrowserCanonicalDefaultPort(t *testing.T) {
	for _, tc := range []struct{ name, listen, origin, want string }{
		{"derived IPv4", "127.0.0.1:80", "", "http://127.0.0.1"},
		{"explicit IPv4 port", "127.0.0.1:8080", "http://127.0.0.1:80", "http://127.0.0.1"},
		{"canonical IPv4", "127.0.0.1:8080", "http://127.0.0.1", "http://127.0.0.1"},
		{"derived IPv6", "[::1]:80", "", "http://[::1]"},
		{"explicit IPv6 port", "[::1]:8080", "http://[::1]:80", "http://[::1]"},
		{"canonical IPv6", "[::1]:8080", "http://[::1]", "http://[::1]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := validEnv()
			values["CHEESETRAP_API_LISTEN"] = tc.listen
			values["CHEESETRAP_API_ORIGIN"] = tc.origin
			cfg, err := Parse([]string{"api"}, env(values))
			if err != nil || cfg.APIOrigin != tc.want {
				t.Errorf("origin=%q error=%v, want %q", cfg.APIOrigin, err, tc.want)
			}
			if err == nil && cfg.APIListen != tc.listen {
				t.Fatal("origin normalization changed listener")
			}
		})
	}
}
func TestAPIOriginRejectsMappedIPv6(t *testing.T) {
	for _, origin := range []string{"http://[::ffff:127.0.0.1]:8080", "http://[::ffff:7f00:1]:8080", "http://[::ffff:127.0.0.1]:80", "http://[::ffff:7f00:1]"} {
		values := validEnv()
		values["CHEESETRAP_API_ORIGIN"] = origin
		if _, err := Parse([]string{"api"}, env(values)); !errors.Is(err, ErrAPIOriginInvalid) {
			t.Errorf("mapped origin=%q error=%v, want invalid origin", origin, err)
		}
	}
}

func TestInstallContainerListenerRequiresExplicitAPIOptInAndOrigin(t *testing.T) {
	for _, tc := range []struct {
		role, listen, opt, origin string
		ok                        bool
	}{
		{"api", "0.0.0.0:8080", "true", "http://127.0.0.1:8080", true},
		{"api", "0.0.0.0:8080", "", "http://127.0.0.1:8080", false},
		{"api", "0.0.0.0:8080", "true", "", false},
		{"api", "[::]:8080", "true", "http://127.0.0.1:8080", false},
		{"api", "192.0.2.1:8080", "true", "http://127.0.0.1:8080", false},
		{"api", "0.0.0.0:8080", "yes", "http://127.0.0.1:8080", false},
		{"worker", "", "true", "", false},
	} {
		values := validEnv()
		values["CHEESETRAP_API_LISTEN"] = tc.listen
		values["CHEESETRAP_API_CONTAINER_LISTENER"] = tc.opt
		values["CHEESETRAP_API_ORIGIN"] = tc.origin
		_, err := Parse([]string{tc.role}, env(values))
		if (err == nil) != tc.ok {
			t.Errorf("role=%s listen=%s opt=%s accepted=%v", tc.role, tc.listen, tc.opt, err == nil)
		}
	}
}
func TestInstallDatabaseURLFileIsExclusiveAndPure(t *testing.T) {
	for _, tc := range []struct {
		url, path string
		ok        bool
	}{
		{"", "/never-read/database-url", true}, {"", "relative", false},
		{"postgres://user:secret@db/name", "/never-read/database-url", false},
		{"", "", false},
	} {
		_, err := Parse([]string{"migrate"}, env(map[string]string{"CHEESETRAP_DATABASE_URL": tc.url, "CHEESETRAP_DATABASE_URL_FILE": tc.path}))
		if (err == nil) != tc.ok {
			t.Errorf("file configuration accepted=%v want=%v", err == nil, tc.ok)
		}
	}
}
