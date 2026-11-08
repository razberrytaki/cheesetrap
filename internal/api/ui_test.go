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
