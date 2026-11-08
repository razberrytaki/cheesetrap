//go:build integration

package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"cheesetrap/internal/store"
)

func TestAuthCLI(t *testing.T) {
	ctx := context.Background()
	migration, err := store.NewPool(ctx, os.Getenv("CHEESETRAP_TEST_MIGRATION_URL"))
	if err != nil {
		t.Fatal("isolated database required")
	}
	defer migration.Close()
	_, _ = migration.Exec(ctx, "DELETE FROM cheesetrap.sessions; DELETE FROM cheesetrap.admins")
	t.Cleanup(func() {
		_, _ = migration.Exec(context.Background(), "DELETE FROM cheesetrap.sessions; DELETE FROM cheesetrap.admins")
	})
	binary := filepath.Join(t.TempDir(), "cheesetrap")
	build := exec.Command("go", "build", "-o", binary, "./cmd/cheesetrap")
	build.Dir = "../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %s", out)
	}
	environment := []string{"CHEESETRAP_DATABASE_URL=" + os.Getenv("CHEESETRAP_TEST_API_URL")}
	create := exec.Command(binary, "admin", "create")
	create.Env = environment
	create.Stdin = strings.NewReader("admin\ncorrect horse battery staple\n")
	out, err := create.CombinedOutput()
	if err != nil {
		t.Fatalf("admin create failed; output=%s", out)
	}
	if strings.Contains(string(out), "correct horse") || strings.Contains(string(out), "postgresql://") {
		t.Fatal("admin command leaked credentials")
	}
	var hash string
	if migration.QueryRow(ctx, "SELECT password_hash FROM cheesetrap.admins WHERE username='admin'").Scan(&hash) != nil || !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatal("CLI did not hash password")
	}
	duplicate := exec.Command(binary, "admin", "create")
	duplicate.Env = environment
	duplicate.Stdin = strings.NewReader("other\ncorrect horse battery staple\n")
	if duplicate.Run() == nil {
		t.Fatal("second administrator accepted")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	_ = l.Close()
	server := exec.Command(binary, "api")
	server.Env = append(environment, "CHEESETRAP_API_LISTEN="+address)
	if err := server.Start(); err != nil {
		t.Fatal("API start failed")
	}
	exited := make(chan error, 1)
	go func() { exited <- server.Wait() }()
	t.Cleanup(func() { _ = server.Process.Kill() })
	client := &http.Client{Timeout: time.Second}
	t.Cleanup(client.CloseIdleConnections)
	origin := "http://" + address
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get(origin + "/api/v1/health/ready")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		select {
		case <-exited:
			t.Fatal("API exited before ready")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("API never ready")
		}
		time.Sleep(25 * time.Millisecond)
	}
	resp, err := client.Get(origin + "/api/v1/auth/csrf")
	if err != nil {
		t.Fatal("HTTP bootstrap failed")
	}
	var csrf struct {
		Token string `json:"csrf_token"`
	}
	if json.NewDecoder(resp.Body).Decode(&csrf) != nil {
		t.Fatal("bootstrap decode failed")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	cookies := resp.Cookies()
	req, _ := http.NewRequest("POST", origin+"/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"correct horse battery staple"}`))
	req.Header.Set("Origin", origin)
	req.Header.Set("X-CSRF-Token", csrf.Token)
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal("HTTP login failed")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("HTTP login status=%d", resp.StatusCode)
	}
	client.CloseIdleConnections()
	_ = server.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-exited:
		if err != nil {
			t.Fatal("API termination failed")
		}
	// net/http may wait five seconds for a newly accepted connection.
	// Allow the configured ten-second shutdown grace plus process scheduling.
	case <-time.After(12 * time.Second):
		t.Fatal("API termination timed out")
	}
	// A blocked stdin pipe must not strand the graceful shutdown path.
	blocked := exec.Command(binary, "admin", "create")
	blocked.Env = environment
	pipe, err := blocked.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	if blocked.Start() != nil {
		t.Fatal("blocked admin start failed")
	}
	done := make(chan error, 1)
	go func() { done <- blocked.Wait() }()
	time.Sleep(150 * time.Millisecond)
	_ = blocked.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("blocked input termination failed")
		}
	case <-time.After(2 * time.Second):
		_ = blocked.Process.Kill()
		t.Fatal("blocked input ignored termination")
	}
	for i := range 2 {
		path := filepath.Join(t.TempDir(), "schema.json")
		cmd := exec.Command(binary, "api-schema", "--out", path)
		cmd.Env = []string{}
		if cmd.Run() != nil {
			t.Fatal("pure schema CLI failed")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("schema missing")
		}
		if i == 0 {
			hash = string(data)
		} else if hash != string(data) {
			t.Fatal("schema nondeterministic")
		}
		var schema map[string]any
		if json.Unmarshal(data, &schema) != nil || !strings.Contains(string(data), "/api/v1/events") {
			t.Fatal("schema contract invalid")
		}
	}
}
