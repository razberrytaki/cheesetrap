package loadtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/ssh"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{IsolatedTest: true, ExternalEnrichmentDisabled: true, HTTPURL: "http://127.0.0.1:8080", Concurrency: 2, Timeout: "1s"}
}
func TestIsolationAndBounds(t *testing.T) {
	s := Scenario{Name: "smoke", Duration: "100ms", HTTPPerSecond: 10}
	c := validConfig()
	if err := c.Validate(s); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.IsolatedTest = false }, func(c *Config) { c.ExternalEnrichmentDisabled = false }, func(c *Config) { c.HTTPURL = "http://example.com" }, func(c *Config) { c.HTTPURL = "http://127.0.0.1:80@evil.test" }, func(c *Config) { c.Concurrency = 10000 }, func(c *Config) { c.Timeout = "0s" }} {
		bad := c
		mutate(&bad)
		if bad.Validate(s) == nil {
			t.Fatalf("accepted unsafe config: %#v", bad)
		}
	}
	for _, duration := range []string{"0s", "24h", "bad"} {
		bad := s
		bad.Duration = duration
		if c.Validate(bad) == nil {
			t.Fatal("accepted duration", duration)
		}
	}
	s.HTTPPerSecond = -1
	if c.Validate(s) == nil {
		t.Fatal("accepted negative rate")
	}
}
func TestHTTPExchangeAndReport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/synthetic" {
			t.Error(r.URL.Path)
		}
		w.WriteHeader(404)
	}))
	defer server.Close()
	c := validConfig()
	c.HTTPURL = server.URL
	s := Scenario{Name: "smoke", Duration: "150ms", HTTPPerSecond: 20}
	report, err := Run(context.Background(), c, s)
	if err != nil {
		t.Fatal(err)
	}
	if report.HTTP.Succeeded < 2 || report.HTTP.Failed != 0 {
		t.Fatalf("%+v", report)
	}
	b, _ := json.Marshal(report)
	if strings.Contains(string(b), "password") || strings.Contains(string(b), server.URL) {
		t.Fatal("report exposes config")
	}
	if report.NormalizedEventsPerSecond != nil {
		t.Fatal("input rate falsely reported as normalized EPS")
	}
}
func TestBoundedConcurrencyAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(80 * time.Millisecond) }))
	defer server.Close()
	c := validConfig()
	c.HTTPURL = server.URL
	c.Concurrency = 1
	ctx, cancel := context.WithTimeout(context.Background(), 130*time.Millisecond)
	defer cancel()
	start := time.Now()
	report, err := Run(ctx, c, Scenario{Name: "bounded", Duration: "1s", HTTPPerSecond: 200})
	if err != nil {
		t.Fatal(err)
	}
	if report.HTTP.Dropped == 0 {
		t.Fatal("overload not counted")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("cancellation failed")
	}
}

func TestRejectRedirectAndUntrustedTLS(t *testing.T) {
	var reached bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer redirect.Close()
	c := validConfig()
	c.HTTPURL = redirect.URL
	if _, err := Run(context.Background(), c, Scenario{Duration: "20ms", HTTPPerSecond: 50}); err != nil {
		t.Fatal(err)
	}
	if reached {
		t.Fatal("followed redirect")
	}
	c.HTTPSURL = "https://127.0.0.1:443"
	c.TLSCAFile = ""
	if c.Validate(Scenario{Duration: "1s", HTTPSPerSecond: 1}) == nil {
		t.Fatal("TLS trust omitted")
	}
}

func TestSSHFailureFixtureAndHostKeyVerification(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	cfg := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if meta.User() != "synthetic-invalid-user" || string(password) != "synthetic-invalid-password" {
			t.Error("unexpected fixture")
		}
		attempts.Add(1)
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer conn.Close(); ssh.NewServerConn(conn, cfg) }()
		}
	}()
	keyfile := filepath.Join(t.TempDir(), "host.pub")
	os.WriteFile(keyfile, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0600)
	c := validConfig()
	c.SSHAddress = listener.Addr().String()
	c.SSHHostKeyFile = keyfile
	scenario := Scenario{Duration: "20ms", SSHPerSecond: 50}
	report, err := Run(context.Background(), c, scenario)
	if err != nil {
		t.Fatal(err)
	}
	if report.SSH.Succeeded != 1 || attempts.Load() != 1 {
		t.Fatalf("failure auth not recognized: %+v", report)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	wrong, _ := ssh.NewSignerFromKey(other)
	os.WriteFile(keyfile, ssh.MarshalAuthorizedKey(wrong.PublicKey()), 0600)
	report, err = Run(context.Background(), c, scenario)
	if err != nil {
		t.Fatal(err)
	}
	if report.SSH.Failed != 1 || attempts.Load() != 1 {
		t.Fatal("host key mismatch sent credentials")
	}
	listener.Close()
	<-done
}

func TestTLSVerifiesCertificateAndName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	c := validConfig()
	c.HTTPSURL = server.URL
	c.TLSCAFile = ca
	c.TLSServerName = "example.com"
	s := Scenario{Duration: "20ms", HTTPSPerSecond: 50}
	report, err := Run(context.Background(), c, s)
	if err != nil {
		t.Fatal(err)
	}
	if report.HTTPS.Succeeded != 1 {
		t.Fatalf("trusted cert failed: %+v", report)
	}
	c.TLSServerName = "wrong.invalid"
	report, err = Run(context.Background(), c, s)
	if err != nil {
		t.Fatal(err)
	}
	if report.HTTPS.Failed != 1 {
		t.Fatal("hostname mismatch accepted")
	}
}

func TestDeterministicDetectionPathMix(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { paths = append(paths, r.URL.Path); w.WriteHeader(404) }))
	defer server.Close()
	c := validConfig()
	c.HTTPURL = server.URL
	c.Concurrency = 1
	s := Scenario{Duration: "300ms", HTTPPerSecond: 20, WebWorkload: "detection-mix-v1"}
	report, err := Run(context.Background(), c, s)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"/synthetic", "/.env", "/.git/config", "/wp-login.php", "/wp-admin", "/phpmyadmin"}
	if !reflect.DeepEqual(paths, expected) {
		t.Fatalf("paths = %v", paths)
	}
	if report.WebWorkload != "detection-mix-v1" || !reflect.DeepEqual(report.WebPathCycle, expected) {
		t.Fatalf("missing workload metadata: %+v", report)
	}
	s.WebWorkload = "unknown"
	if c.Validate(s) == nil {
		t.Fatal("unknown workload accepted")
	}
}

func TestTinyPositiveRateCompletesOneInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer server.Close()
	c := validConfig()
	c.HTTPURL = server.URL
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	report, err := Run(ctx, c, Scenario{Duration: "30ms", HTTPPerSecond: 1e-300})
	if err != nil {
		t.Fatal(err)
	}
	if report.Cancelled || report.HTTP.Scheduled != 1 || report.HTTP.Succeeded != 1 || report.HTTP.Dropped != 0 {
		t.Fatalf("tiny rate overflows scheduler: %+v", report)
	}
}
func TestNonFiniteRatesRejected(t *testing.T) {
	c := validConfig()
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		for _, s := range []Scenario{{Duration: "1s", HTTPPerSecond: value}, {Duration: "1s", HTTPPerSecond: 1, SSHPerSecond: value}, {Duration: "1s", HTTPPerSecond: 1, HTTPSPerSecond: value}, {Duration: "1s", HTTPPerSecond: 1, TargetNormalizedEPS: value}} {
			if c.Validate(s) == nil {
				t.Fatalf("accepted nonfinite value: %+v", s)
			}
		}
	}
}
