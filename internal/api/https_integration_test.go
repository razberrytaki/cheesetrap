//go:build integration

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The existing Testcontainers runner supplies the DB. Both proxy listeners are
// owned loopback fixtures; no production URL, certificate or credential is used.
func TestHTTPSProxyAuth(t *testing.T) {
	pool, _, _ := apiFixture(t)
	proxy := httptest.NewUnstartedServer(nil)
	origin := "https://" + proxy.Listener.Addr().String()
	backend := httptest.NewServer(NewHandler(pool, origin))
	defer backend.Close()
	upstream, _ := url.Parse(backend.URL)
	proxy.Config.Handler = httputil.NewSingleHostReverseProxy(upstream)
	proxy.StartTLS()
	defer proxy.Close()
	client := proxy.Client() // Trust only the fixture's own TLS certificate.
	client.Jar, _ = cookiejar.New(nil)
	client.Timeout = 5 * time.Second
	defer client.CloseIdleConnections()
	call := func(method, path, body, requestOrigin, token string, want int) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, origin+path, strings.NewReader(body))
		req.Header.Set("Origin", requestOrigin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("HTTPS fixture request failed", err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		if resp.StatusCode != want {
			t.Fatalf("%s %s status=%d want=%d", method, path, resp.StatusCode, want)
		}
		return resp
	}
	csrfToken := func(resp *http.Response) string {
		t.Helper()
		var body struct {
			Token string `json:"csrf_token"`
		}
		if json.NewDecoder(resp.Body).Decode(&body) != nil || body.Token == "" {
			t.Fatal("missing HTTPS CSRF token")
		}
		resp.Body.Close()
		return body.Token
	}
	assertCookies := func(resp *http.Response, count int, deleted bool) {
		t.Helper()
		if len(resp.Cookies()) != count {
			t.Fatal("missing HTTPS cookies")
		}
		for _, c := range resp.Cookies() {
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Domain != "" || c.Path != cookiePath || (c.MaxAge < 0) != deleted {
				t.Fatal("HTTPS cookie attributes incorrect")
			}
		}
	}
	boot := call("GET", "/api/v1/auth/csrf", "", "", "", 200)
	assertCookies(boot, 1, false)
	token := csrfToken(boot)
	const credentials = `{"username":"admin","password":"correct horse battery staple"}`
	call("POST", "/api/v1/auth/login", credentials, "https://evil.invalid", token, 403).Body.Close()
	call("POST", "/api/v1/auth/login", credentials, origin, "", 403).Body.Close()
	login := call("POST", "/api/v1/auth/login", credentials, origin, token, 200)
	assertCookies(login, 2, false)
	rotated := csrfToken(login)
	if rotated == token {
		t.Fatal("login did not rotate CSRF")
	}
	call("GET", "/api/v1/auth/me", "", "", "", 200).Body.Close()
	call("POST", "/api/v1/auth/logout", "", origin, token, 403).Body.Close()
	logout := call("POST", "/api/v1/auth/logout", "", origin, rotated, 200)
	assertCookies(logout, 2, true)
	logout.Body.Close()
	call("GET", "/api/v1/auth/me", "", "", "", 401).Body.Close()
	// Loopback callers still need the configured Host; no health-route bypass.
	resp, err := http.Get(backend.URL + "/api/v1/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("backend accepted an unconfigured Host")
	}
	if os.Getenv("CHEESETRAP_E2E_RUN") == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "node", "node_modules/@playwright/test/cli.js", "test", "--config=playwright.https.config.ts")
		cmd.Dir = "../../web"
		for _, key := range []string{"PATH", "HOME", "TMPDIR", "LANG"} {
			if value := os.Getenv(key); value != "" {
				cmd.Env = append(cmd.Env, key+"="+value)
			}
		}
		cmd.Env = append(cmd.Env, "CHEESETRAP_E2E_RUN=1", "CHEESETRAP_E2E_HTTPS_URL="+origin)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("HTTPS browser flow failed: %s", out)
		}
		t.Log("Chromium HTTPS login, secure cookies, reload and logout passed")
	}
}
