//go:build release

package ui

import (
	"io/fs"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestReleaseContainsBuiltUIAndServesEveryAsset(t *testing.T) {
	index, err := fs.ReadFile(assets(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(index), "Development UI resource") {
		t.Fatal("development placeholder in release")
	}
	paths := regexp.MustCompile(`(?:src|href)="(/assets/[^\"]+)"`).FindAllStringSubmatch(string(index), -1)
	if len(paths) < 2 {
		t.Fatal("release needs actual generated script and stylesheet")
	}
	for _, match := range paths {
		for _, method := range []string{"GET", "HEAD"} {
			w := httptest.NewRecorder()
			uiHandler().ServeHTTP(w, httptest.NewRequest(method, match[1], nil))
			if w.Code != 200 {
				t.Fatalf("asset=%s status=%d", match[1], w.Code)
			}
			if method == "GET" && w.Body.Len() == 0 {
				t.Fatal("empty generated asset")
			}
			if method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD asset returned a body")
			}
			if strings.Contains(w.Header().Get("Content-Type"), "text/html") {
				t.Fatal("asset request fell back to SPA")
			}
		}
	}
}
