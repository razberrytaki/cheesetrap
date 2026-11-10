// Package api exposes only the private, implemented management API.
package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cheesetrap/internal/auth"
	"cheesetrap/internal/config"
	"cheesetrap/internal/ui"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const sessionCookie = "cheesetrap_session"
const csrfCookie = "cheesetrap_csrf"
const cookiePath = "/api/v1"

type requestParentKey struct{}

type proofResponseWriter struct {
	http.ResponseWriter
	proof, wroteHeader bool
}

func (w *proofResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *proofResponseWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		if w.proof {
			// Computation may be long; transmitting the response remains bounded.
			_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(15 * time.Second))
		}
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *proofResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Keep middleware values while using the original request's cancellation and
// deadline. Only authenticated proof commands opt out of the short API budget.
type proofCommandContext struct {
	context.Context
	values context.Context
}

func (c proofCommandContext) Value(key any) any { return c.values.Value(key) }

func completeProofCommand(ctx huma.Context, next func(huma.Context)) {
	parent, ok := ctx.Context().Value(requestParentKey{}).(context.Context)
	if !ok {
		next(ctx)
		return
	}
	_, w := humachi.Unwrap(ctx)
	if writer, ok := w.(*proofResponseWriter); ok {
		writer.proof = true
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	next(huma.WithContext(ctx, proofCommandContext{Context: parent, values: ctx.Context()}))
}

type server struct {
	pool         *pgxpool.Pool
	auth         *auth.Service
	origin, host string
	csrfKey      []byte
}

func NewHandler(pool *pgxpool.Pool, origin string) http.Handler {
	handler, _ := newAPI(pool, origin)
	return handler
}
func newAPI(pool *pgxpool.Pool, origin string) (http.Handler, huma.API) {
	origin, err := config.CanonicalAPIOrigin(origin)
	if err != nil {
		panic("invalid_api_origin")
	}
	parsed, _ := url.Parse(origin)
	s := &server{pool: pool, auth: auth.NewService(pool), origin: origin, host: parsed.Host, csrfKey: make([]byte, 32)}
	if _, err := rand.Read(s.csrfKey); err != nil {
		panic("random_source_unavailable")
	}
	r := chi.NewRouter()
	r.Use(s.protect)
	r.NotFound(ui.Handler(writeError).ServeHTTP)
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) { writeError(w, r, 405) })
	cfg := huma.DefaultConfig("Cheesetrap private management API", "1.0.0")
	cfg.OpenAPIPath = ""
	cfg.DocsPath = ""
	cfg.SchemasPath = ""
	cfg.CreateHooks = nil
	cfg.RejectUnknownQueryParameters = true
	cfg.Formats = map[string]huma.Format{"application/json": {Marshal: func(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }, Unmarshal: json.Unmarshal}}
	cfg.Components.SecuritySchemes = map[string]*huma.SecurityScheme{"session": {Type: "apiKey", In: "cookie", Name: sessionCookie}, "csrf": {Type: "apiKey", In: "header", Name: "X-CSRF-Token"}}
	cfg.Transformers = []huma.Transformer{func(ctx huma.Context, _ string, v any) (any, error) {
		if e, ok := v.(*Error); ok {
			e.RequestID = requestID(ctx.Context())
		}
		return v, nil
	}}
	a := humachi.New(r, cfg)
	s.registerAuth(a)
	s.registerEvents(a)
	s.registerHealth(a)
	s.registerReports(a)
	s.registerReportCommands(a)
	s.registerSettings(a)
	s.registerContactRefresh(a)
	// Huma's nullable tag supports scalars only; the wire value is an object or null.
	schemas := a.OpenAPI().Components.Schemas.Map()
	latestGap := schemas["SensorStatus"].Properties["last_gap"]
	schemas["SensorStatus"].Properties["last_gap"] = &huma.Schema{AnyOf: []*huma.Schema{latestGap, {Type: "null"}}}
	return r, a
}

// Schema uses the identical registrations as runtime and never connects or
// listens. Maps are sorted by encoding/json; random security state is omitted.
func Schema() ([]byte, error) {
	_, a := newAPI(nil, "http://127.0.0.1:8080")
	return json.MarshalIndent(a.OpenAPI(), "", "  ")
}
func (s *server) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			panic("random_source_unavailable")
		}
		rid := hex.EncodeToString(id)
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey, rid))
		w.Header().Set("X-Request-ID", rid)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Host != s.host || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			if r.Method == http.MethodGet && r.Header.Get("Sec-Fetch-Dest") == "document" {
				ui.WriteAddressGuidance(w)
				return
			}
			writeError(w, r, 403)
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" && origin != s.origin {
			writeError(w, r, 403)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			cookie := cookieValue(r, csrfCookie)
			token := r.Header.Get("X-CSRF-Token")
			if origin != s.origin || !s.validCSRF(cookie, cookieValue(r, sessionCookie)) || len(token) != len(cookie) || subtle.ConstantTimeCompare([]byte(token), []byte(cookie)) != 1 {
				writeError(w, r, 403)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		parent := r.Context()
		ctx, cancel := context.WithTimeout(context.WithValue(parent, requestParentKey{}, parent), 10*time.Second)
		defer cancel()
		next.ServeHTTP(&proofResponseWriter{ResponseWriter: w}, r.WithContext(ctx))
	})
}
func cookieValue(r *http.Request, name string) string {
	value := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			value = c.Value
			count++
		}
	}
	if count != 1 {
		return ""
	}
	return value
}
func (s *server) csrfToken(session string) string {
	nonce := auth.RandomToken()
	return nonce + "." + s.csrfMAC(nonce, session)
}
func (s *server) csrfMAC(nonce, session string) string {
	mac := hmac.New(sha256.New, s.csrfKey)
	_, _ = mac.Write([]byte(nonce + "\x00" + session))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (s *server) validCSRF(token, session string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 2 && auth.ValidToken(parts[0]) && auth.ValidToken(parts[1]) && hmac.Equal([]byte(parts[1]), []byte(s.csrfMAC(parts[0], session)))
}
func (s *server) secureCookie(name, value string, maxAge int) http.Cookie {
	// Use the configured browser origin, never the HTTP proxy hop or untrusted
	// forwarding headers, to protect both issuance and deletion cookies.
	return http.Cookie{Name: name, Value: value, Path: cookiePath, MaxAge: maxAge, HttpOnly: true, Secure: strings.HasPrefix(s.origin, "https://"), SameSite: http.SameSiteStrictMode}
}
func (s *server) requireSession(ctx huma.Context, next func(huma.Context)) {
	r, w := humachi.Unwrap(ctx)
	identity, err := s.auth.Authenticate(ctx.Context(), cookieValue(r, sessionCookie))
	if err != nil {
		status := 401
		if err == auth.ErrUnavailable {
			status = 503
		}
		writeError(w, r, status)
		return
	}
	next(huma.WithValue(ctx, identityKey, identity))
}
