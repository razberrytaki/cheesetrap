package web

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func SupplementalCases() []Case {
	var out []Case
	for _, p := range []string{"http", "https"} {
		out = append(out, Case{ID: p + "-login-control", Protocol: p, Input: Input{Method: "GET", Target: "/index.html"}})
		for _, pair := range []struct {
			name, raw  string
			disconnect bool
		}{
			{"redaction", "POST /submit?token=m0-secret-query&safe=ok HTTP/1.1\r\nHost: m0.test.invalid\r\nAuthorization: Bearer m0-secret-auth\r\nCookie: session=m0-secret-cookie\r\nX-Api-Key: m0-secret-key\r\nContent-Type: application/json\r\nContent-Length: 29\r\nConnection: close\r\n\r\n{\"password\":\"m0-secret-body\"}", false},
			{"chunked", "POST /chunk HTTP/1.1\r\nHost: m0.test.invalid\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n4\r\ntest\r\n0\r\n\r\n", false},
			{"disconnect", "POST /partial HTTP/1.1\r\nHost: m0.test.invalid\r\nContent-Type: text/plain\r\nExpect: 100-continue\r\nContent-Length: 100\r\n\r\npartial", true},
			{"malformed-secret", "GET /?token=m0-secret-query HTTP/1.1\r\nBroken-m0-secret-header\r\n\r\n", false},
			{"truncated-json", framedBody("application/json", `{"password":"m0-secret-`+strings.Repeat("S", BodyLimit+18)), false},
			{"truncated-form", framedBody("application/x-www-form-urlencoded", "password=m0-secret-"+strings.Repeat("S", BodyLimit+7)), false},
		} {
			out = append(out, Case{ID: p + "-" + pair.name, Protocol: p, Input: Input{Raw: pair.raw, Disconnect: pair.disconnect}})
		}
	}
	return out
}

func framedBody(contentType, body string) string {
	return fmt.Sprintf("POST /submit HTTP/1.1\r\nHost: m0.test.invalid\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", contentType, len(body), body)
}

func TestSupplementalCompleteBodiesMatchContentLength(t *testing.T) {
	for _, c := range SupplementalCases() {
		if c.Input.Disconnect || strings.Contains(c.ID, "malformed") {
			continue
		}
		raw, _ := c.Bytes("sensor.test.invalid")
		request, e := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if e != nil {
			t.Fatal(c.ID, e)
		}
		if request.ContentLength >= 0 {
			_, body, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
			if int64(len(body)) != request.ContentLength {
				t.Fatalf("%s declared=%d actual=%d", c.ID, request.ContentLength, len(body))
			}
		}
	}
}
