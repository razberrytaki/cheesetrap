package api

import (
	"cheesetrap/internal/store/db"
	"context"
	"github.com/danielgtaylor/huma/v2"
	"time"
)

type healthOutput struct {
	Body struct {
		Status string `json:"status"`
	}
}

func (s *server) registerHealth(a huma.API) {
	for _, kind := range []string{"live", "ready"} {
		huma.Register(a, huma.Operation{OperationID: "health-" + kind, Method: "GET", Path: "/api/v1/health/" + kind, Summary: "Minimal " + kind + " probe", Errors: []int{403, 503}}, func(ctx context.Context, _ *struct{}) (*healthOutput, error) {
			if kind == "ready" {
				if s.pool == nil {
					return nil, apiError(503)
				}
				ctx, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				if ready, err := db.New(s.pool).CheckAPIReady(ctx); err != nil || ready == nil || !*ready {
					return nil, apiError(503)
				}
			}
			out := &healthOutput{}
			out.Body.Status = "ok"
			return out, nil
		})
	}
}
