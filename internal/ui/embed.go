// Package ui serves the embedded management interface.
package ui

import (
	"bytes"
	"io/fs"
	"mime"
	"net/http"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"time"
)

// Handler serves only known UI routes and real generated assets. Its caller
// supplies the API's fixed error envelope and applies Host/Origin protection.
var reportRouteID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func Handler(onError func(http.ResponseWriter, *http.Request, int)) http.Handler {
	files := assets()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path
		escaped := strings.ToLower(r.URL.EscapedPath())
		if path.Clean(name) != name || strings.ContainsAny(name, "\\%\x00") || strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
			onError(w, r, http.StatusNotFound)
			return
		}
		isPage := name == "/" || name == "/overview" || name == "/events" || name == "/reports" || name == "/settings"
		if strings.HasPrefix(name, "/ips/") {
			_, err := netip.ParseAddr(strings.TrimPrefix(name, "/ips/"))
			isPage = err == nil
		}
		if strings.HasPrefix(name, "/reports/") {
			isPage = reportRouteID.MatchString(strings.TrimPrefix(name, "/reports/"))
		}
		isAsset := strings.HasPrefix(name, "/assets/") && len(name) > len("/assets/")
		if !isPage && !isAsset {
			onError(w, r, http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			onError(w, r, http.StatusMethodNotAllowed)
			return
		}
		if isPage {
			name = "index.html"
		} else {
			name = strings.TrimPrefix(name, "/")
		}
		data, err := fs.ReadFile(files, name)
		if err != nil {
			onError(w, r, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", mime.TypeByExtension(path.Ext(name)))
		setPageHeaders(w)
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	})
}

func setPageHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
}

// The page is static because a DNS-rebinding page can read this response, so
// it must not reveal the configured origin.
const addressGuidance = `<!doctype html>
<html lang="ko">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>관리 화면 주소를 확인하세요 · cheesetrap</title>
<main>
<h1>관리 화면 주소를 확인하세요</h1>
<p>cheesetrap 관리 화면은 설치할 때 설정한 관리 주소로만 열립니다.</p>
<ul>
<li>SSH 터널을 쓴다면 주소창에 <code>http://127.0.0.1:8080</code>을 직접 입력하세요. <code>localhost</code>나 다른 로컬 포트로는 열리지 않습니다.</li>
<li>HTTPS 프록시를 쓴다면 설정한 <code>api_origin</code> 주소로 여세요.</li>
<li>다른 사이트의 링크로는 열리지 않습니다. 주소를 직접 입력하거나 북마크를 쓰세요.</li>
</ul>
</main>
</html>
`

// WriteAddressGuidance answers a rejected page navigation with instructions
// instead of the API error envelope.
func WriteAddressGuidance(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setPageHeaders(w)
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(addressGuidance))
}
