package api

import (
	"context"
	"net/http"
	"time"

	"cheesetrap/internal/auth"
	"github.com/danielgtaylor/huma/v2"
)

type csrfInput struct {
	Session string `cookie:"cheesetrap_session"`
	CSRF    string `cookie:"cheesetrap_csrf"`
}
type csrfOutput struct {
	Cookies []http.Cookie `header:"Set-Cookie"`
	Body    struct {
		CSRFToken string `json:"csrf_token"`
	}
}
type loginInput struct {
	Session string `cookie:"cheesetrap_session"`
	Body    struct {
		Username string `json:"username" minLength:"1" maxLength:"64"`
		Password string `json:"password" minLength:"1" maxLength:"1024"`
	}
}
type loginOutput struct {
	Cookies []http.Cookie `header:"Set-Cookie"`
	Body    struct {
		Admin     auth.Identity `json:"admin"`
		CSRFToken string        `json:"csrf_token"`
	}
}
type meOutput struct{ Body auth.Identity }
type logoutInput struct {
	Session string `cookie:"cheesetrap_session"`
}
type logoutOutput struct {
	Cookies []http.Cookie `header:"Set-Cookie"`
	Body    struct {
		LoggedOut bool `json:"logged_out"`
	}
}

func (s *server) registerAuth(a huma.API) {
	huma.Register(a, huma.Operation{OperationID: "auth-csrf", Method: "GET", Path: "/api/v1/auth/csrf", Summary: "Bootstrap a session-bound CSRF token", Errors: []int{403}}, func(ctx context.Context, in *csrfInput) (*csrfOutput, error) {
		token := in.CSRF
		if !s.validCSRF(token, in.Session) {
			token = s.csrfToken(in.Session)
		}
		out := &csrfOutput{Cookies: []http.Cookie{s.secureCookie(csrfCookie, token, int(auth.SessionLifetime.Seconds()))}}
		out.Body.CSRFToken = token
		return out, nil
	})
	huma.Register(a, huma.Operation{OperationID: "auth-login", Method: "POST", Path: "/api/v1/auth/login", Summary: "Sign in the locally provisioned administrator", Description: "Requires exact configured Origin and Host, CSRF cookie and X-CSRF-Token. Rotates session and CSRF tokens. The JSON body is limited to 8 KiB to accommodate escaped passwords up to 1024 UTF-8 bytes.", MaxBodyBytes: 8 * 1024, BodyReadTimeout: 5 * time.Second, Errors: []int{401, 403, 413, 422, 503}, Security: []map[string][]string{{"csrf": {}}}}, func(ctx context.Context, in *loginInput) (*loginOutput, error) {
		session, err := s.auth.Login(ctx, in.Body.Username, in.Body.Password, in.Session)
		if err != nil {
			if err == auth.ErrCredentials {
				return nil, apiError(401)
			}
			return nil, apiError(503)
		}
		csrf := s.csrfToken(session.Token)
		out := &loginOutput{Cookies: []http.Cookie{s.secureCookie(sessionCookie, session.Token, int(auth.SessionLifetime.Seconds())), s.secureCookie(csrfCookie, csrf, int(auth.SessionLifetime.Seconds()))}}
		out.Body.Admin = session.Identity
		out.Body.CSRFToken = csrf
		return out, nil
	})
	huma.Register(a, huma.Operation{OperationID: "auth-me", Method: "GET", Path: "/api/v1/auth/me", Summary: "Read the authenticated administrator", Middlewares: huma.Middlewares{s.requireSession}, Errors: []int{401, 403, 503}, Security: []map[string][]string{{"session": {}}}}, func(ctx context.Context, _ *struct{}) (*meOutput, error) {
		return &meOutput{Body: ctx.Value(identityKey).(auth.Identity)}, nil
	})
	huma.Register(a, huma.Operation{OperationID: "auth-logout", Method: "POST", Path: "/api/v1/auth/logout", Summary: "Revoke this session", Middlewares: huma.Middlewares{s.requireSession}, Errors: []int{401, 403, 503}, Security: []map[string][]string{{"session": {}, "csrf": {}}}}, func(ctx context.Context, in *logoutInput) (*logoutOutput, error) {
		if s.auth.Logout(ctx, in.Session) != nil {
			return nil, apiError(503)
		}
		out := &logoutOutput{Cookies: []http.Cookie{s.secureCookie(sessionCookie, "", -1), s.secureCookie(csrfCookie, "", -1)}}
		out.Body.LoggedOut = true
		return out, nil
	})
}
