package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func uiHandler() http.Handler {
	return Handler(func(w http.ResponseWriter, _ *http.Request, code int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "error"})
	})
}
func TestEmbeddedPageAndHead(t *testing.T) {
	for _, route := range []string{"/", "/overview", "/events", "/reports", "/reports/00000000-0000-4000-8000-000000000001", "/ips/192.0.2.10", "/ips/2001:db8::1", "/settings"} {
		for _, method := range []string{"GET", "HEAD"} {
			t.Run(method+route, func(t *testing.T) {
				w := httptest.NewRecorder()
				uiHandler().ServeHTTP(w, httptest.NewRequest(method, route, nil))
				if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
					t.Fatalf("status=%d content-type=%s", w.Code, w.Header().Get("Content-Type"))
				}
				if method == "GET" && !strings.Contains(w.Body.String(), "<title>cheesetrap") {
					t.Fatal("embedded page missing")
				}
				if method == "HEAD" && w.Body.Len() != 0 {
					t.Fatal("HEAD returned a body")
				}
				if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
					t.Fatal("missing document CSP")
				}
			})
		}
	}
}
func TestSPAFallbackNeverMasksAPIMethodAssetsOrTraversal(t *testing.T) {
	cases := []struct {
		method, path string
		status       int
	}{
		{"GET", "/deliveries", 404}, {"GET", "/deliveries/00000000-0000-4000-8000-000000000001", 404},
		{"GET", "/api", 404}, {"GET", "/api/", 404}, {"GET", "/api/v1/missing", 404},
		{"GET", "/api/v1/events", 404}, {"POST", "/api/v1/missing", 404},
		{"POST", "/", 405}, {"PUT", "/events", 405}, {"OPTIONS", "/", 405},
		{"GET", "/reports/not-a-uuid", 404}, {"GET", "/ips/not-an-ip", 404}, {"GET", "/reports/id/extra", 404}, {"GET", "/missing", 404}, {"GET", "/openapi.json", 404}, {"GET", "/docs", 404},
		{"GET", "/assets/missing.js", 404}, {"GET", "/assets/", 404}, {"POST", "/assets/missing.js", 405},
		{"GET", "/assets/../index.html", 404}, {"GET", "/assets/%2e%2e/index.html", 404},
		{"GET", "/assets/%252e%252e/index.html", 404}, {"GET", "/assets%2f../index.html", 404},
		{"GET", "/assets/%5c..%5cindex.html", 404}, {"GET", "//events", 404},
	}
	for _, tc := range cases {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			uiHandler().ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			if !strings.Contains(w.Header().Get("Content-Type"), "application/json") || strings.Contains(w.Body.String(), "<!doctype") {
				t.Fatal("fallback masked failure with HTML")
			}
		})
	}
}
