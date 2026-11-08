//go:build integration

package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"cheesetrap/internal/ingestion"
	"cheesetrap/internal/store"
)

func TestInstallHTTPSConfiguration(t *testing.T) {
	out := filepath.Join(t.TempDir(), "install")
	prepare := exec.Command("python3", "-B", "scripts/install-prepare.py", "--config", "deploy/config.https.example.yaml", "--output", out)
	prepare.Dir = "../.."
	if err := prepare.Run(); err != nil {
		t.Fatal("HTTPS example installation failed")
	}
	cmd := exec.Command("docker", "compose", "--env-file", filepath.Join(out, "compose.env"), "-f", "deploy/compose.yaml", "--profile", "*", "config", "--format", "json")
	cmd.Dir = "../.."
	data, err := cmd.Output()
	if err != nil {
		t.Fatal("HTTPS installation compose failed")
	}
	var rendered struct {
		Services map[string]struct {
			Environment map[string]string
			Ports       []struct {
				HostIP    string `json:"host_ip"`
				Published string
			}
		}
	}
	if json.Unmarshal(data, &rendered) != nil {
		t.Fatal("invalid compose output")
	}
	api := rendered.Services["api"]
	if api.Environment["CHEESETRAP_API_ORIGIN"] != "https://dashboard.example.com" || api.Environment["CHEESETRAP_API_LISTEN"] != "0.0.0.0:8080" {
		t.Fatal("HTTPS origin not passed to API")
	}
	if len(api.Ports) != 1 || api.Ports[0].HostIP != "127.0.0.1" || api.Ports[0].Published != "8080" || len(rendered.Services["postgres"].Ports) != 0 {
		t.Fatal("HTTPS changed host publication")
	}
	for name, service := range rendered.Services {
		if name != "api" && service.Environment["CHEESETRAP_API_ORIGIN"] != "" {
			t.Fatal("HTTPS origin leaked to another role")
		}
	}
}

func TestInstallConfiguration(t *testing.T) {
	cmd := exec.Command("python3", "scripts/test_install.py")
	cmd.Dir = "../.."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("installation behavior: %s", output)
	}
	cmd = exec.Command("docker", "compose", "-f", "deploy/compose.yaml", "--profile", "*", "config", "--format", "json")
	cmd.Dir = "../.."
	data, err := cmd.Output()
	if err != nil {
		t.Fatal("compose config failed")
	}
	var cfg struct {
		Services map[string]struct {
			Image       string
			Environment map[string]string
			CPUs        float64     `json:"cpus"`
			MemoryLimit json.Number `json:"mem_limit"`
			Ports       []struct {
				HostIP    string `json:"host_ip"`
				Published string
			}
			Volumes []struct {
				Source, Target string
				ReadOnly       bool `json:"read_only"`
			}
			Networks map[string]any
			Profiles []string
			Restart  string
			Tmpfs    []string
			Sysctls  map[string]string
		}
		Networks map[string]struct{ Internal bool }
	}
	if json.Unmarshal(data, &cfg) != nil {
		t.Fatal("compose JSON invalid")
	}
	t.Run("load_balancer_backend_binding", func(t *testing.T) {
		cmd := exec.Command("docker", "compose", "-f", "deploy/compose.yaml", "--profile", "*", "config", "--format", "json")
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), "SENSOR_BIND_IP=10.20.0.10", "SENSOR_SSH_PORT=2222", "SENSOR_HTTP_PORT=18080", "SENSOR_HTTPS_PORT=18443")
		data, err := cmd.Output()
		if err != nil {
			t.Fatal("load balancer compose config failed")
		}
		var rendered struct {
			Services map[string]struct {
				Ports []struct {
					HostIP    string `json:"host_ip"`
					Published string
					Target    int
				}
			}
		}
		if json.Unmarshal(data, &rendered) != nil {
			t.Fatal("load balancer compose JSON invalid")
		}
		ssh := rendered.Services["cowrie"].Ports
		web := rendered.Services["web"].Ports
		if len(ssh) != 1 || ssh[0].HostIP != "10.20.0.10" || ssh[0].Published != "2222" || ssh[0].Target != 2222 || len(web) != 2 || web[0].HostIP != "10.20.0.10" || web[0].Published != "18080" || web[0].Target != 8080 || web[1].HostIP != "10.20.0.10" || web[1].Published != "18443" || web[1].Target != 8443 {
			t.Fatal("load balancer backends are not confined to their dedicated private address and host ports")
		}
		api := rendered.Services["api"].Ports
		if len(api) != 1 || api[0].HostIP != "127.0.0.1" || api[0].Published != "8080" || len(rendered.Services["postgres"].Ports) != 0 {
			t.Fatal("load balancer binding changed the management boundary")
		}
	})
	api := cfg.Services["api"]
	if len(api.Ports) != 1 || api.Ports[0].HostIP != "127.0.0.1" || api.Ports[0].Published != "8080" {
		t.Fatal("API not confined to IPv4 host loopback")
	}
	if len(cfg.Services["postgres"].Ports) != 0 || !cfg.Networks["management"].Internal {
		t.Fatal("database or management network exposed")
	}
	if api.Restart != "no" {
		t.Fatal("API must not restart before its host guard")
	}
	if cfg.Services["collector"].Restart != "no" {
		t.Fatal("collector must wait for explicit archive refresh before restarting")
	}
	for name, service := range cfg.Services {
		if name != "postgres" && service.Restart != "no" {
			t.Fatal("only PostgreSQL may restart automatically")
		}
	}
	if len(api.Networks) != 2 {
		t.Fatal("API needs its host-publication bridge plus internal DB bridge")
	}
	if _, ok := api.Networks["api_host"]; !ok || cfg.Networks["api_host"].Internal {
		t.Fatal("API publication bridge must permit Docker host port mapping")
	}
	for name, service := range cfg.Services {
		if name != "api" {
			if _, ok := service.Networks["api_host"]; ok {
				t.Fatal("API host-publication network leaked to another role")
			}
		}
	}
	credentials := map[string]bool{}
	for _, role := range []string{"api", "collector", "migrate", "worker"} {
		service := cfg.Services[role]
		if service.Image != api.Image {
			t.Fatal("roles do not share one image")
		}
		if len(service.Tmpfs) != 1 || !strings.Contains(service.Tmpfs[0], "size=16m") {
			t.Fatal("app tmpfs is not bounded")
		}
		for _, mount := range service.Volumes {
			if mount.Target == "/run/secrets/database-url" {
				if !mount.ReadOnly || credentials[mount.Source] {
					t.Fatal("database credential mount reused/writable")
				}
				credentials[mount.Source] = true
			}
		}
	}
	if len(credentials) != 4 {
		t.Fatal("role database mounts missing")
	}
	for _, mount := range cfg.Services["collector"].Volumes {
		if !mount.ReadOnly {
			t.Fatal("collector can write mounted files")
		}
	}
	if cfg.Networks["worker_egress"].Internal {
		t.Fatal("registry egress must permit outbound connections")
	}
	worker := cfg.Services["worker"]
	if len(worker.Profiles) != 1 || worker.Profiles[0] != "worker" || worker.Restart != "no" {
		t.Fatal("worker must remain opt-in")
	}
	for _, role := range []string{"cowrie", "web"} {
		sensor := cfg.Services[role]
		if len(sensor.Networks) != 1 || sensor.Networks["sensor"] == nil || sensor.Restart != "no" {
			t.Fatal("sensor network/restart policy unsafe")
		}
		if sensor.Sysctls["net.ipv6.conf.all.disable_ipv6"] != "1" || sensor.Sysctls["net.ipv6.conf.default.disable_ipv6"] != "1" {
			t.Fatal("sensor IPv6 must be explicitly disabled until supported")
		}
		for _, mount := range sensor.Volumes {
			if strings.Contains(mount.Source, "secrets") || mount.Target == "/var/run/docker.sock" {
				t.Fatal("sensor sees management credentials/control socket")
			}
		}
	}
	for _, name := range []string{"base"} {
		t.Run(name, func(t *testing.T) {
			effective := cfg
			roleEnvironment := map[string]map[string]string{
				"migrate": {}, "admin": {},
				"api":       {"CHEESETRAP_API_LISTEN": "0.0.0.0:8080", "CHEESETRAP_API_CONTAINER_LISTENER": "true", "CHEESETRAP_API_ORIGIN": "http://127.0.0.1:8080"},
				"collector": {"CHEESETRAP_STORAGE_PATHS": "/logs:/storage/postgres", "CHEESETRAP_COLLECTOR_LOG_DIR": "/logs", "CHEESETRAP_COLLECTOR_SOURCES_FILE": "/config/sources.json"},
				"worker":    {"CHEESETRAP_STORAGE_PATHS": "/logs:/storage/postgres"},
			}
			for role, want := range roleEnvironment {
				service, exists := effective.Services[role]
				if !exists {
					t.Fatalf("Go role %s missing", role)
				}
				if service.Environment["GOMEMLIMIT"] != "192MiB" {
					t.Errorf("%s GOMEMLIMIT=%q, want 192MiB", role, service.Environment["GOMEMLIMIT"])
				}
				memory, err := service.MemoryLimit.Int64()
				if err != nil || memory != 256*1024*1024 || service.CPUs != 1 {
					t.Errorf("%s hard limits changed: memory=%s cpus=%g", role, service.MemoryLimit, service.CPUs)
				}
				want["CHEESETRAP_DATABASE_URL_FILE"] = "/run/secrets/database-url"
				for key, value := range want {
					got, present := service.Environment[key]
					if !present || got != value {
						t.Errorf("%s lost environment %s: got=%q want=%q", role, key, got, value)
					}
				}
			}
			for role, service := range effective.Services {
				if _, exists := service.Environment["GOGC"]; exists {
					t.Errorf("%s overrides default GOGC", role)
				}
				if _, isGo := roleEnvironment[role]; !isGo {
					if _, exists := service.Environment["GOMEMLIMIT"]; exists {
						t.Errorf("non-Go role %s received GOMEMLIMIT", role)
					}
				}
				if _, present := service.Environment["CHEESETRAP_SMTP_SECRET_FILE"]; present {
					t.Errorf("%s SMTP secret environment leaked", role)
				}
				for _, mount := range service.Volumes {
					if mount.Target == "/run/secrets/smtp.json" {
						t.Errorf("%s SMTP secret mount leaked", role)
					}
				}
				_, egress := service.Networks["worker_egress"]
				if egress != (role == "worker") {
					t.Errorf("%s registry egress leaked or missing", role)
				}
			}
		})
	}
}

// This test consumes only the runner-owned acceptance database. Dedicated URLs
// keep its single collector lease/admin separate from other packages in ./....
func TestInstallIngestionAndManagement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	database := func(role string) string {
		value := os.Getenv("CHEESETRAP_TEST_INSTALL_" + role + "_URL")
		if value == "" {
			t.Fatal("fresh installation acceptance database is required")
		}
		return value
	}
	pool, err := store.NewPool(ctx, database("MIGRATION"))
	if err != nil {
		t.Fatal("acceptance database unavailable")
	}
	defer pool.Close()
	binary := filepath.Join(t.TempDir(), "cheesetrap")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/cheesetrap")
	build.Dir = "../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %s", out)
	}
	private := t.TempDir()
	secret := func(role string) string {
		p := filepath.Join(private, role+"-url")
		if os.WriteFile(p, []byte(database(role)+"\n"), 0600) != nil {
			t.Fatal("secret write")
		}
		return "CHEESETRAP_DATABASE_URL_FILE=" + p
	}
	apiSecret, collectorSecret := secret("API"), secret("COLLECTOR")
	create := exec.CommandContext(ctx, binary, "admin", "create")
	create.Env = []string{apiSecret}
	create.Stdin = strings.NewReader("install-admin\ninstallation acceptance secret\n")
	if out, err := create.CombinedOutput(); err != nil {
		t.Fatalf("admin create failed: %s", out)
	}
	logs := filepath.Join(t.TempDir(), "logs")
	if os.MkdirAll(logs, 0700) != nil {
		t.Fatal("logs dir")
	}
	sources := []ingestion.Source{{SensorID: "10000000-0000-4000-8000-000000000707", Name: "install-sensor", Engine: "cowrie", Path: "cowrie.json", ArchivePaths: []string{"cowrie.json.1"}, IsTest: true, Endpoints: []ingestion.Endpoint{{Service: "ssh", ObservedIP: "172.30.91.10", ObservedPort: 2222, PublicIP: "192.0.2.10", PublicPort: 2222}}}}
	manifest := filepath.Join(private, "sources.json")
	data, _ := json.Marshal(sources)
	if os.WriteFile(manifest, data, 0600) != nil {
		t.Fatal("manifest write")
	}
	line := func(n int) []byte {
		return []byte(fmt.Sprintf(`{"eventid":"cowrie.session.connect","timestamp":"%s","src_ip":"198.51.100.20","src_port":34567,"dst_ip":"172.30.91.10","dst_port":2222,"session":"install%d"}`+"\n", time.Now().UTC().Format(time.RFC3339Nano), n))
	}
	active := filepath.Join(logs, "cowrie.json")
	if os.WriteFile(active, line(1), 0600) != nil {
		t.Fatal("initial source")
	}
	start := func(role string, env []string) func() {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, role)
		cmd.Env = env
		if cmd.Start() != nil {
			t.Fatal("role start")
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		stopped := false
		halt := func() {
			if stopped {
				return
			}
			stopped = true
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case err := <-done:
				if err != nil {
					t.Error("role shutdown failed")
				}
			case <-time.After(12 * time.Second):
				_ = cmd.Process.Kill()
				t.Error("role shutdown timeout")
			}
		}
		t.Cleanup(halt)
		return halt
	}
	collectorEnv := []string{collectorSecret, "CHEESETRAP_COLLECTOR_LOG_DIR=" + logs, "CHEESETRAP_COLLECTOR_SOURCES_FILE=" + manifest}
	stop := start("collector", collectorEnv)
	await := func(want int) {
		t.Helper()
		for {
			var count int
			err := pool.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.events WHERE sensor_id=$1", sources[0].SensorID).Scan(&count)
			if err == nil && count == want {
				return
			}
			if ctx.Err() != nil {
				t.Fatal("event count never reached expected value")
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	await(1)
	stop()
	// A stopped collector must resolve the saved generation at an explicitly
	// configured archive path, then read the replacement with no lost/duplicate row.
	if os.Rename(active, filepath.Join(logs, "cowrie.json.1")) != nil || os.WriteFile(active, line(2), 0600) != nil {
		t.Fatal("rename and replacement")
	}
	stop = start("collector", collectorEnv)
	await(2)
	stop()
	stop = start("collector", collectorEnv)
	var checkpoint time.Time
	if pool.QueryRow(ctx, "SELECT max(updated_at) FROM cheesetrap.checkpoints WHERE sensor_id=$1", sources[0].SensorID).Scan(&checkpoint) != nil {
		t.Fatal("checkpoint absent")
	}
	for {
		var newer time.Time
		if pool.QueryRow(ctx, "SELECT max(updated_at) FROM cheesetrap.checkpoints WHERE sensor_id=$1", sources[0].SensorID).Scan(&newer) == nil && newer.After(checkpoint) {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("restart observation absent")
		}
		time.Sleep(25 * time.Millisecond)
	}
	await(2)
	stop()
	var total, generations int
	var source, destination string
	if pool.QueryRow(ctx, "SELECT count(*),count(DISTINCT file_generation_id),min(host(source_ip)),min(host(destination_ip)) FROM cheesetrap.events WHERE sensor_id=$1", sources[0].SensorID).Scan(&total, &generations, &source, &destination) != nil || total != 2 || generations != 2 || source != "198.51.100.20" || destination != "192.0.2.10" {
		t.Fatal("source/destination mapping or durable generation count wrong")
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("test listener")
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	origin := fmt.Sprintf("http://127.0.0.1:%d", port)
	stopAPI := start("api", []string{apiSecret, fmt.Sprintf("CHEESETRAP_API_LISTEN=0.0.0.0:%d", port), "CHEESETRAP_API_CONTAINER_LISTENER=true", "CHEESETRAP_API_ORIGIN=" + origin})
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: time.Second}
	defer client.CloseIdleConnections()
	for {
		resp, err := client.Get(origin + "/api/v1/health/ready")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if ctx.Err() != nil {
			t.Fatal("API wildcard listener never became ready")
		}
		time.Sleep(25 * time.Millisecond)
	}
	response := func(req *http.Request, want int) []byte {
		t.Helper()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("HTTP request failed")
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("HTTP status=%d want=%d", resp.StatusCode, want)
		}
		return body
	}
	req, _ := http.NewRequest("GET", origin+"/api/v1/auth/csrf", nil)
	var csrf struct {
		Token string `json:"csrf_token"`
	}
	if json.Unmarshal(response(req, 200), &csrf) != nil || csrf.Token == "" {
		t.Fatal("CSRF token missing")
	}
	login := func(requestOrigin string) *http.Request {
		req, _ := http.NewRequest("POST", origin+"/api/v1/auth/login", strings.NewReader(`{"username":"install-admin","password":"installation acceptance secret"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", requestOrigin)
		req.Header.Set("X-CSRF-Token", csrf.Token)
		return req
	}
	response(login("http://127.0.0.2:"+fmt.Sprint(port)), 403)
	response(login(origin), 200)
	req, _ = http.NewRequest("GET", origin+"/api/v1/events?source_ip=198.51.100.20", nil)
	var events struct {
		Items []struct {
			DestinationIP string `json:"destination_ip"`
			IsTest        bool   `json:"is_test"`
		}
	}
	if json.Unmarshal(response(req, 200), &events) != nil || len(events.Items) != 2 || events.Items[0].DestinationIP != "192.0.2.10" || !events.Items[0].IsTest {
		t.Fatal("authenticated UI event endpoint lost ingestion evidence")
	}
	req, _ = http.NewRequest("GET", origin+"/", nil)
	if !strings.Contains(string(response(req, 200)), "<!doctype html>") {
		t.Fatal("embedded UI missing")
	}
	req, _ = http.NewRequest("GET", origin+"/api/v1/events", nil)
	req.Host = "evil.invalid"
	response(req, 403)
	client.CloseIdleConnections()
	stopAPI()
	stopWorker := start("worker", []string{secret("WORKER")})
	for {
		var ingested, detected int64
		if pool.QueryRow(ctx, "SELECT ingested_seq,detected_seq FROM cheesetrap.processing_cursors").Scan(&ingested, &detected) == nil && ingested == 2 && detected == 2 {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("worker did not process collected evidence")
		}
		time.Sleep(25 * time.Millisecond)
	}
	stopWorker()
	var samples, attempts, schedules int
	if pool.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.events WHERE is_test").Scan(&samples) != nil || samples != 2 {
		t.Fatal("installation samples lost their test marker")
	}
	if pool.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.delivery_attempts").Scan(&attempts) != nil || attempts != 0 {
		t.Fatal("installation generated a delivery attempt")
	}
	if pool.QueryRow(ctx, "SELECT count(*) FROM cheesetrap.delivery_schedule").Scan(&schedules) != nil || schedules != 0 {
		t.Fatal("installation queued sample delivery")
	}
}
