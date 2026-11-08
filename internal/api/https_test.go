package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPSOriginProxyBoundary(t *testing.T) {
	defer func() {
		if recover() != nil {
			t.Fatal("configured HTTPS origin rejected")
		}
	}()
	const origin = "https://dashboard.example.com"
	h := NewHandler(nil, origin+":443")
	call := func(method, path, host, requestOrigin, token string, cookies []*http.Cookie, fetchSite string) *httptest.ResponseRecorder {
		// The proxy-to-app hop is HTTP. Neither TLS nor forwarding headers determine trust.
		r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(`{"username":123}`))
		r.Host = host
		r.Header.Set("Origin", requestOrigin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", token)
		r.Header.Set("Sec-Fetch-Site", fetchSite)
		r.Header.Set("X-Forwarded-Host", "dashboard.example.com")
		r.Header.Set("X-Forwarded-Proto", "http")
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	boot := call("GET", "/api/v1/auth/csrf", "dashboard.example.com", "", "", nil, "")
	if boot.Code != 200 {
		t.Fatalf("bootstrap status=%d", boot.Code)
	}
	var body struct {
		Token string `json:"csrf_token"`
	}
	if json.Unmarshal(boot.Body.Bytes(), &body) != nil || body.Token == "" {
		t.Fatal("missing token")
	}
	cookies := boot.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Domain != "" {
		t.Fatal("HTTPS cookie protection missing")
	}
	if call("POST", "/api/v1/auth/login", "dashboard.example.com", origin, body.Token, cookies, "same-origin").Code != 422 {
		t.Fatal("valid proxy request did not reach input validation")
	}
	if call("GET", "/api/v1/events", "dashboard.example.com", "", "", nil, "").Code != 401 {
		t.Fatal("HTTPS bypassed login")
	}
	for _, tc := range []struct{ host, origin, token, site string }{
		{"evil.invalid", origin, body.Token, ""},
		{"127.0.0.1:8080", origin, body.Token, ""},
		{"dashboard.example.com:443", origin, body.Token, ""},
		{"dashboard.example.com", "https://evil.invalid", body.Token, ""},
		{"dashboard.example.com", "http://dashboard.example.com", body.Token, ""},
		{"dashboard.example.com", origin + ":443", body.Token, ""},
		{"dashboard.example.com", "", body.Token, ""},
		{"dashboard.example.com", origin, "", ""},
		{"dashboard.example.com", origin, body.Token, "cross-site"},
	} {
		if call("POST", "/api/v1/auth/login", tc.host, tc.origin, tc.token, cookies, tc.site).Code != 403 {
			t.Fatal("HTTPS boundary accepted foreign host/origin or missing CSRF")
		}
	}
}
