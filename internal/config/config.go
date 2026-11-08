// Package config parses role configuration without performing file or network I/O.
package config

import (
	"errors"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Role string

const (
	API       Role = "api"
	APISchema Role = "api-schema"
	Collector Role = "collector"
	Worker    Role = "worker"
	Migrate   Role = "migrate"
	Admin     Role = "admin"
)

// Errors are stable codes. They never include arguments or environment values.
var (
	ErrHelp                    = errors.New("help")
	ErrInvalidCommand          = errors.New("invalid_command")
	ErrDatabaseURLRequired     = errors.New("database_url_required")
	ErrDatabaseURLInvalid      = errors.New("database_url_invalid")
	ErrDatabaseURLFileInvalid  = errors.New("database_url_file_invalid")
	ErrShutdownGraceInvalid    = errors.New("shutdown_grace_invalid")
	ErrRemovedSMTPOption       = errors.New("smtp_configuration_removed")
	ErrRoleOption              = errors.New("role_option_forbidden")
	ErrAPIListenInvalid        = errors.New("api_listen_invalid")
	ErrAPIOriginInvalid        = errors.New("api_origin_invalid")
	ErrCollectorLogDirRequired = errors.New("collector_log_dir_required")
	ErrCollectorSourcesInvalid = errors.New("collector_sources_file_invalid")
	ErrCollectorLogDirInvalid  = errors.New("collector_log_dir_invalid")
)

type LookupEnv func(string) (string, bool)

// Config contains credentials and paths and must never be logged as a whole.
// DatabaseURL syntax validation does not establish connectivity or privileges.
type Config struct {
	Role                 Role
	DatabaseURL          string
	DatabaseURLFile      string
	APIContainerListener bool
	ShutdownGrace        time.Duration
	APIListen            string
	APIOrigin            string
	SchemaOutput         string
	CollectorLogDir      string
	CollectorSourcesFile string
}

// Parse accepts api, collector, worker, migrate, or admin create. Nonempty
// role-specific environment variables are rejected outside their owning role.
// Empty values are treated as unset. Unknown environment variables are ignored.
func Parse(args []string, lookup LookupEnv) (Config, error) {
	role, err := parseRole(args)
	if err != nil {
		return Config{}, err
	}
	get := func(key string) string {
		if lookup == nil {
			return ""
		}
		value, _ := lookup(key)
		return value
	}
	cfg := Config{
		Role:                 role,
		DatabaseURL:          get("CHEESETRAP_DATABASE_URL"),
		DatabaseURLFile:      get("CHEESETRAP_DATABASE_URL_FILE"),
		ShutdownGrace:        10 * time.Second,
		APIListen:            get("CHEESETRAP_API_LISTEN"),
		APIOrigin:            get("CHEESETRAP_API_ORIGIN"),
		CollectorLogDir:      get("CHEESETRAP_COLLECTOR_LOG_DIR"),
		CollectorSourcesFile: get("CHEESETRAP_COLLECTOR_SOURCES_FILE"),
	}
	if get("CHEESETRAP_SMTP_SECRET_FILE") != "" || get("CHEESETRAP_SMTP_TEST_RECIPIENT") != "" {
		return Config{}, ErrRemovedSMTPOption
	}
	containerListener := get("CHEESETRAP_API_CONTAINER_LISTENER")
	if (containerListener != "" && role != API) || (cfg.APIListen != "" && role != API) ||
		(cfg.APIOrigin != "" && role != API) ||
		(cfg.CollectorLogDir != "" && role != Collector) ||
		(cfg.CollectorSourcesFile != "" && role != Collector) {
		return Config{}, ErrRoleOption
	}
	if role == APISchema {
		cfg.SchemaOutput = args[2]
		return cfg, nil
	}
	if cfg.DatabaseURLFile != "" && (cfg.DatabaseURL != "" || !filepath.IsAbs(cfg.DatabaseURLFile) || filepath.Clean(cfg.DatabaseURLFile) != cfg.DatabaseURLFile) {
		return Config{}, ErrDatabaseURLFileInvalid
	}
	if cfg.DatabaseURL == "" && cfg.DatabaseURLFile == "" {
		return Config{}, ErrDatabaseURLRequired
	}
	if cfg.DatabaseURL != "" && !ValidDatabaseURL(cfg.DatabaseURL) {
		return Config{}, ErrDatabaseURLInvalid
	}
	if value := get("CHEESETRAP_SHUTDOWN_GRACE"); value != "" {
		cfg.ShutdownGrace, err = time.ParseDuration(value)
		if err != nil || cfg.ShutdownGrace <= 0 || cfg.ShutdownGrace > 5*time.Minute {
			return Config{}, ErrShutdownGraceInvalid
		}
	}
	switch role {
	case API:
		if containerListener != "" && containerListener != "true" {
			return Config{}, ErrAPIListenInvalid
		}
		cfg.APIContainerListener = containerListener == "true"
		if cfg.APIListen == "" {
			cfg.APIListen = "127.0.0.1:8080"
		}
		address, err := netip.ParseAddrPort(cfg.APIListen)
		if err != nil || (!address.Addr().IsLoopback() && !(cfg.APIContainerListener && address.Addr() == netip.IPv4Unspecified())) || address.Addr().Zone() != "" || address.Port() == 0 {
			return Config{}, ErrAPIListenInvalid
		}
		if cfg.APIContainerListener && cfg.APIOrigin == "" {
			return Config{}, ErrAPIOriginInvalid
		}
		if cfg.APIOrigin == "" {
			cfg.APIOrigin = "http://" + cfg.APIListen
		}
		cfg.APIOrigin, err = CanonicalAPIOrigin(cfg.APIOrigin)
		if err != nil {
			return Config{}, err
		}
	case Collector:
		if cfg.CollectorLogDir == "" {
			return Config{}, ErrCollectorLogDirRequired
		}
		if !filepath.IsAbs(cfg.CollectorLogDir) || filepath.Clean(cfg.CollectorLogDir) != cfg.CollectorLogDir {
			return Config{}, ErrCollectorLogDirInvalid
		}
		if !filepath.IsAbs(cfg.CollectorSourcesFile) || filepath.Clean(cfg.CollectorSourcesFile) != cfg.CollectorSourcesFile {
			return Config{}, ErrCollectorSourcesInvalid
		}
		relative, err := filepath.Rel(cfg.CollectorLogDir, cfg.CollectorSourcesFile)
		if err != nil || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			return Config{}, ErrCollectorSourcesInvalid
		}
	}
	return cfg, nil
}

func parseRole(args []string) (Role, error) {
	if len(args) == 3 && args[0] == "api-schema" && args[1] == "--out" && args[2] != "" {
		return APISchema, nil
	}
	if len(args) == 1 {
		switch args[0] {
		case "help", "-h", "--help":
			return "", ErrHelp
		case string(API), string(Collector), string(Worker), string(Migrate):
			return Role(args[0]), nil
		}
	}
	if len(args) == 2 && args[0] == "admin" && args[1] == "create" {
		return Admin, nil
	}
	return "", ErrInvalidCommand
}

// ValidDatabaseURL checks syntax without echoing or opening credentials.
func ValidDatabaseURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") ||
		parsed.Hostname() == "" || strings.TrimPrefix(parsed.Path, "/") == "" ||
		parsed.Fragment != "" || strings.HasSuffix(parsed.Host, ":") {
		return false
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return false
		}
	}
	return true
}

var originDNSLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var originNumericLabel = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]+)$`)

// CanonicalAPIOrigin accepts one literal loopback HTTP origin or an explicitly
// configured HTTPS origin behind a trusted proxy. It never changes the listener.
// Require browser-canonical ASCII spelling, except that default ports are removed.
func CanonicalAPIOrigin(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", ErrAPIOriginInvalid
	}
	host := u.Hostname()
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Is4In6() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || (u.Scheme == "http" && !address.IsLoopback()) {
			return "", ErrAPIOriginInvalid
		}
		host = address.String()
		if address.Is6() {
			host = "[" + host + "]"
		}
	} else {
		if u.Scheme != "https" || len(host) > 253 {
			return "", ErrAPIOriginInvalid
		}
		labels := strings.Split(host, ".")
		for _, label := range labels {
			if !originDNSLabel.MatchString(label) {
				return "", ErrAPIOriginInvalid
			}
		}
		// Browsers interpret numeric final labels as IPv4, including shorthand,
		// octal and hexadecimal forms. Only netip's canonical IP form is supported.
		if originNumericLabel.MatchString(labels[len(labels)-1]) {
			return "", ErrAPIOriginInvalid
		}
	}
	canonical := u.Scheme + "://" + host
	if port := u.Port(); port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 || strconv.FormatUint(number, 10) != port || value != canonical+":"+port {
			return "", ErrAPIOriginInvalid
		}
		if !(u.Scheme == "http" && number == 80 || u.Scheme == "https" && number == 443) {
			canonical += ":" + port
		}
	} else if value != canonical {
		return "", ErrAPIOriginInvalid
	}
	return canonical, nil
}

// ValidAPIOrigin reports whether an origin is supported configuration input.
func ValidAPIOrigin(value string) bool {
	_, err := CanonicalAPIOrigin(value)
	return err == nil
}
