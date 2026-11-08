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
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	})
}
