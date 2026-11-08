package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testOrigin = "http://127.0.0.1:8080"

// Exercise the same router used in production with no database for boundary tests.
func testHandler() http.Handler { return NewHandler(nil, testOrigin) }
func request(h http.Handler, method, path, body string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, testOrigin+path, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestAuthUnauthenticatedAndNoSignup(t *testing.T) {
	h := testHandler()
	for _, path := range []string{"/api/v1/auth/me", "/api/v1/events", "/api/v1/overview", "/api/v1/reports", "/api/v1/settings"} {
		w := request(h, "GET", path, "", nil)
		if w.Code != 401 {
			t.Errorf("%s status=%d want401", path, w.Code)
		}
	}
	for _, path := range []string{"/api/v1/auth/signup", "/openapi.json", "/docs"} {
		w := request(h, "GET", path, "", nil)
		if w.Code != 404 {
			t.Errorf("unregistered %s status=%d", path, w.Code)
		}
	}
}
func TestAuthOriginHostCSRFAndErrorEnvelope(t *testing.T) {
	h := testHandler()
	bootstrap := request(h, "GET", "/api/v1/auth/csrf", "", nil)
	if bootstrap.Code != 200 {
		t.Fatalf("CSRF bootstrap status=%d", bootstrap.Code)
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if json.Unmarshal(bootstrap.Body.Bytes(), &body) != nil || len(body.CSRFToken) < 40 {
		t.Fatal("missing CSRF token")
	}
	cookies := bootstrap.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Secure || cookies[0].Domain != "" {
		t.Fatal("unsafe CSRF cookie")
	}
	for _, tc := range []struct{ name, origin, token, host string }{
		{"no origin", "", body.CSRFToken, ""}, {"foreign origin", "http://evil.invalid", body.CSRFToken, ""},
		{"no token", testOrigin, "", ""}, {"wrong token", testOrigin, strings.Repeat("a", 43), ""},
		{"wrong host", testOrigin, body.CSRFToken, "evil.invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", testOrigin+"/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"secret-value"}`))
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-CSRF-Token", tc.token)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Forwarded-Host", "127.0.0.1:8080")
			r.Header.Set("X-Forwarded-Proto", "http")
			if tc.host != "" {
				r.Host = tc.host
			}
			for _, c := range cookies {
				r.AddCookie(c)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("status=%d want403", w.Code)
			}
			assertError(t, w, "secret-value")
		})
	}
	for _, headers := range []map[string]string{{"Origin": "http://evil.invalid"}, {"Sec-Fetch-Site": "cross-site"}} {
		w := request(h, "GET", "/api/v1/auth/csrf", "", headers)
		if w.Code != 403 {
			t.Fatal("cross-origin bootstrap accepted")
		}
	}
	w := request(h, "GET", "/missing", "", map[string]string{"X-Request-ID": "attacker-secret"})
	assertError(t, w, "attacker-secret")
	w = request(h, "PUT", "/api/v1/auth/csrf", "", map[string]string{"Origin": testOrigin, "X-CSRF-Token": body.CSRFToken}, cookies...)
	if w.Code != 405 {
		t.Fatalf("method status=%d", w.Code)
	}
	assertError(t, w, "")
	for _, tc := range []struct{ name, password, secret string }{
		{"plain", "validation-secret", "validation-secret"},
		{"script", "<script>secret()</script>", "secret()"},
	} {
		t.Run("validation_"+tc.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{"username": 123, "password": tc.password})
			if err != nil {
				t.Fatal(err)
			}
			w := request(h, "POST", "/api/v1/auth/login", string(payload), map[string]string{"Origin": testOrigin, "X-CSRF-Token": body.CSRFToken, "Content-Type": "application/json", "X-Forwarded-Host": "127.0.0.1:8080"}, cookies...)
			if w.Code != 422 {
				t.Fatalf("validation status=%d", w.Code)
			}
			assertError(t, w, tc.secret)
		})
	}
}
func assertError(t *testing.T, w *httptest.ResponseRecorder, secret string) {
	t.Helper()
	var body map[string]any
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body) != 3 || body["code"] == "" || body["message"] == "" || body["request_id"] != w.Header().Get("X-Request-ID") || len(w.Header().Get("X-Request-ID")) != 32 {
		t.Fatalf("invalid error envelope: status=%d", w.Code)
	}
	if secret != "" && strings.Contains(w.Body.String(), secret) {
		t.Fatal("error reflected input")
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing response protection")
	}
}

func TestAuthBodyLimitsAndSessionBoundCSRF(t *testing.T) {
	h := testHandler()
	w := request(h, "GET", "/api/v1/auth/csrf", "", nil)
	var b struct {
		Token string `json:"csrf_token"`
	}
	if json.Unmarshal(w.Body.Bytes(), &b) != nil {
		t.Fatal("bootstrap decode failed")
	}
	cookies := w.Result().Cookies()
	headers := map[string]string{"Origin": testOrigin, "X-CSRF-Token": b.Token, "Content-Type": "application/json"}
	w = request(h, "POST", "/api/v1/auth/login", strings.Repeat("x", 8*1024+1), headers, cookies...)
	if w.Code != 413 {
		t.Fatalf("unbounded login body status=%d", w.Code)
	}
	assertError(t, w, "")
	w = request(h, "POST", "/api/v1/auth/signup", `{}`, headers, cookies...)
	if w.Code != 404 {
		t.Fatal("signup route registered")
	}
	assertError(t, w, "")
	// A token issued without a session is unusable after a session cookie changes.
	cookies = append(cookies, &http.Cookie{Name: sessionCookie, Value: strings.Repeat("A", 43)})
	w = request(h, "POST", "/api/v1/auth/login", `{}`, headers, cookies...)
	if w.Code != 403 {
		t.Fatal("CSRF not bound to session")
	}
	// A process restart invalidates old CSRF signatures and permits a bootstrap.
	restarted := testHandler()
	w = request(restarted, "POST", "/api/v1/auth/login", `{}`, headers, cookies[:1]...)
	if w.Code != 403 {
		t.Fatal("old process CSRF accepted")
	}
	w = request(restarted, "GET", "/api/v1/auth/csrf", "", nil, cookies[:1]...)
	if w.Code != 200 {
		t.Fatal("CSRF recovery failed")
	}
}
func TestHealthAndSchemaContract(t *testing.T) {
	h := testHandler()
	if request(h, "GET", "/api/v1/health/live", "", nil).Code != 200 {
		t.Fatal("liveness failed")
	}
	w := request(h, "GET", "/api/v1/health/ready", "", nil)
	if w.Code != 503 {
		t.Fatal("no database reported ready")
	}
	assertError(t, w, "")
	first, err := Schema()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Schema()
	if err != nil || string(first) != string(second) {
		t.Fatal("schema nondeterministic")
	}
	var schema struct {
		Paths      map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Type any `json:"type"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(first, &schema) != nil || len(schema.Paths) != 20 {
		t.Fatal("unexpected registered API surface")
	}
	if schema.Components.Schemas["EvidenceView"].Properties["ingestion_seq"].Type != "string" {
		t.Fatal("evidence bigint schema lost string override")
	}
	if schema.Components.Schemas["SelectContactInputBody"].Properties["current_revision_id"].Type != "string" {
		t.Fatal("review expectation omitted by schema")
	}
}

func TestAuthBrowserCanonicalDefaultOrigin(t *testing.T) {
	for _, tc := range []struct{ configured, canonical, host string }{
		{"http://127.0.0.1:80", "http://127.0.0.1", "127.0.0.1"},
		{"http://127.0.0.1", "http://127.0.0.1", "127.0.0.1"},
		{"http://[::1]:80", "http://[::1]", "[::1]"},
		{"http://[::1]", "http://[::1]", "[::1]"},
	} {
		t.Run(tc.configured, func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Fatal("supported default-port origin rejected by router")
				}
			}()
			h := NewHandler(nil, tc.configured)
			call := func(method, path, origin, host, token string, cookies []*http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, tc.canonical+path, strings.NewReader(`{"username":123}`))
				r.Host = host
				r.Header.Set("Origin", origin)
				r.Header.Set("X-CSRF-Token", token)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-Forwarded-Host", tc.host)
				r.Header.Set("X-Forwarded-Proto", "http")
				for _, c := range cookies {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			bootstrap := call("GET", "/api/v1/auth/csrf", tc.canonical, tc.host, "", nil)
			if bootstrap.Code != 200 {
				t.Fatalf("browser-canonical bootstrap status=%d, want200", bootstrap.Code)
			}
			var body struct {
				Token string `json:"csrf_token"`
			}
			if json.Unmarshal(bootstrap.Body.Bytes(), &body) != nil {
				t.Fatal("bootstrap body invalid")
			}
			cookies := bootstrap.Result().Cookies()
			// A valid same-origin unsafe request must reach input validation.
			if got := call("POST", "/api/v1/auth/login", tc.canonical, tc.host, body.Token, cookies).Code; got != 422 {
				t.Fatalf("canonical unsafe request status=%d, want422", got)
			}
			for _, bad := range []struct{ origin, host string }{
				{tc.canonical + ":80", tc.host}, {tc.canonical + ":81", tc.host},
				{tc.canonical, tc.host + ":80"}, {tc.canonical, tc.host + ":81"},
				{"http://127.0.0.1.evil.invalid", tc.host}, {tc.canonical, "127.0.0.1.evil.invalid"},
			} {
				if got := call("POST", "/api/v1/auth/login", bad.origin, bad.host, body.Token, cookies).Code; got != 403 {
					t.Fatalf("nonexact boundary accepted status=%d", got)
				}
			}
		})
	}
}
