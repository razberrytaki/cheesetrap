// Command testpostgres owns the disposable database used by the integration runner.
// Its stdin is a lease: EOF (including parent death) releases the container.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func run() (err error) {
	if len(os.Args) != 4 || !regexp.MustCompile(`^cheesetrap-test-[a-f0-9]{16}$`).MatchString(os.Args[1]) {
		return fmt.Errorf("invalid owned PostgreSQL arguments")
	}
	password := os.Getenv("CHEESETRAP_TEST_BOOTSTRAP_PASSWORD")
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(password) {
		return fmt.Errorf("invalid bootstrap credential")
	}
	var lock struct {
		Files          map[string][]string `json:"files"`
		Testcontainers struct {
			Ryuk string `json:"ryuk"`
		} `json:"testcontainers"`
	}
	data, err := os.ReadFile(os.Args[3])
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, &lock); err != nil {
		return err
	}
	images := lock.Files["deploy/test.compose.yaml"]
	if len(images) != 1 {
		return fmt.Errorf("missing test PostgreSQL image")
	}
	policy, err := newImagePolicy(images[0], lock.Testcontainers.Ryuk)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Watch the lease even during image pulls and startup.
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); stop() }()
	startup, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	logger := log.New(io.Discard, "", 0)
	provider, err := tc.NewDockerProvider(tc.WithLogger(logger), tc.WithDefaultBridgeNetwork(tc.Bridge))
	if err != nil {
		return err
	}
	defer provider.Close()
	api := provider.Client()
	// Testcontainers discovery may fall back when the selected daemon is down.
	// Reject that result before creating networks, images or containers.
	endpoint := os.Getenv("DOCKER_HOST")
	if !strings.HasPrefix(endpoint, "unix://") || api.DaemonHost() != endpoint {
		return fmt.Errorf("Docker provider must use the selected local endpoint")
	}
	provider.SetClient(&lockedDockerClient{APIClient: api, images: policy})
	pids := int64(128)
	port := network.MustParsePort("5432/tcp")
	db, err := provider.CreateContainer(startup, tc.ContainerRequest{
		Name: os.Args[1], Image: images[0], ExposedPorts: []string{"5432/tcp"},
		Env:        map[string]string{"POSTGRES_USER": "postgres", "POSTGRES_DB": "cheesetrap_test", "POSTGRES_PASSWORD": password, "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256"},
		WaitingFor: wait.ForExec([]string{"pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "cheesetrap_test"}).WithStartupTimeout(60 * time.Second),
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = network.PortMap{port: {{HostIP: netip.MustParseAddr("127.0.0.1")}}}
			h.Tmpfs = map[string]string{"/var/lib/postgresql/data": "rw,noexec,nosuid,size=1g"}
			h.ShmSize = 64 << 20
			h.Resources = container.Resources{Memory: 1 << 30, NanoCPUs: 1_000_000_000, PidsLimit: &pids}
			h.LogConfig = container.LogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}}
		},
	})
	if db != nil {
		defer func() {
			if cleanup := tc.TerminateContainer(db); cleanup != nil {
				err = fmt.Errorf("owned PostgreSQL cleanup failed")
			}
		}()
	}
	if err != nil {
		return err
	}
	if err = db.Start(startup); err != nil {
		return err
	}
	mapped, err := db.MappedPort(startup, "5432/tcp")
	if err != nil {
		return err
	}
	inspection, err := db.Inspect(startup)
	if err != nil {
		return err
	}
	bindings := inspection.NetworkSettings.Ports[port]
	if len(bindings) != 1 || bindings[0].HostIP != netip.MustParseAddr("127.0.0.1") || bindings[0].HostPort != mapped.Port() {
		return fmt.Errorf("PostgreSQL must bind only random-port IPv4 loopback")
	}
	metadata, err := json.Marshal(struct {
		Container string `json:"container"`
		Port      string `json:"port"`
	}{db.GetContainerID(), mapped.Port()})
	if err != nil {
		return err
	}
	// The parent polls for an atomic, private readiness record without secrets.
	if err = os.WriteFile(os.Args[2]+".tmp", metadata, 0600); err != nil {
		return err
	}
	if err = os.Rename(os.Args[2]+".tmp", os.Args[2]); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

func main() {
	if err := run(); err != nil {
		// Docker errors can contain credentials; only a fixed category is public.
		fmt.Fprintln(os.Stderr, "Testcontainers PostgreSQL infrastructure failed")
		os.Exit(1)
	}
}
