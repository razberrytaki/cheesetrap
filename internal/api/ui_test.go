package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRuntimeRouterServesUIWithSameHostAndOriginBoundary(t *testing.T) {
	h := testHandler()
	for _, path := range []string{"/", "/events"} {
		w := request(h, "GET", path, "", nil)
		if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("UI %s status=%d", path, w.Code)
		}
		for _, headers := range []map[string]string{{"Origin": "http://evil.invalid"}, {"Sec-Fetch-Site": "cross-site"}} {
			w = request(h, "GET", path, "", headers)
			if w.Code != 403 {
				t.Fatal("UI bypassed origin check")
			}
			assertError(t, w, "")
		}
		r := httptest.NewRequest("GET", testOrigin+path, nil)
		r.Host = "evil.invalid"
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("UI bypassed host check")
		}
		assertError(t, w, "")
	}
	for _, path := range []string{"/api", "/api/", "/api/v1/missing", "/assets/missing.js", "/assets/../index.html"} {
		w := request(h, "GET", path, "", nil)
		if w.Code != 404 {
			t.Fatalf("failure masked for %s: %d", path, w.Code)
		}
		assertError(t, w, "")
	}
}

func TestRejectedPageNavigationExplainsAddressWithoutRevealingOrigin(t *testing.T) {
	const configured = "https://dashboard.example.test"
	h := NewHandler(nil, configured)
	navigate := func(host string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", configured+"/reports", nil)
		r.Host = host
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	document := map[string]string{"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"}
	for _, w := range []*httptest.ResponseRecorder{
		navigate("localhost:8080", document),
		navigate("dashboard.example.test", map[string]string{"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "cross-site"}),
	} {
		if w.Code != 403 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), "관리 화면 주소를 확인하세요") {
			t.Fatalf("rejected navigation gave no guidance: status=%d type=%q", w.Code, w.Header().Get("Content-Type"))
		}
		if strings.Contains(w.Body.String(), "dashboard.example.test") {
			t.Fatal("guidance revealed the configured origin")
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") || w.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatal("guidance page lost UI security headers")
		}
	}
	for _, headers := range []map[string]string{nil, {"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors"}} {
		w := navigate("localhost:8080", headers)
		if w.Code != 403 {
			t.Fatalf("host mismatch status=%d", w.Code)
		}
		assertError(t, w, "dashboard.example.test")
	}
}
