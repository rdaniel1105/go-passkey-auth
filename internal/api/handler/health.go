package handler

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// pingable is the slice of any backend the readiness probe checks. The
// pgxpool.Pool already satisfies this directly; *redis.Client needs a
// tiny adapter (its Ping returns *StatusCmd) — see cmd/server/main.go.
type pingable interface {
	Ping(ctx context.Context) error
}

// HealthDeps bundles the things /health/ready probes. Each field is
// optional in tests; when nil, that subsystem is reported as "skipped"
// and contributes nothing to the overall status.
type HealthDeps struct {
	Logger   *slog.Logger
	Postgres pingable
	Redis    pingable
}

// HealthHandler implements the /health and /health/ready endpoints.
type HealthHandler struct {
	logger   *slog.Logger
	postgres pingable
	redis    pingable
}

type readyResponse struct {
	Status   string `json:"status"`
	Postgres string `json:"postgres,omitempty"`
	Redis    string `json:"redis,omitempty"`
}

// NewHealth constructs a HealthHandler.
func NewHealth(deps HealthDeps) *HealthHandler {
	return &HealthHandler{
		logger:   deps.Logger,
		postgres: deps.Postgres,
		redis:    deps.Redis,
	}
}

// Live handles GET /health. Liveness only — does not probe dependencies.
// Used by orchestrators to decide if the process needs to be restarted.
func (h *HealthHandler) Live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, h.logger, http.StatusOK, map[string]string{"status": "ok"})
}

// Ready handles GET /health/ready. Pings Postgres and Redis with a short
// per-dependency timeout; returns 503 if either is unreachable so load
// balancers can take the instance out of rotation.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	body := readyResponse{Status: "ok"}

	if h.postgres != nil {
		body.Postgres = pingStatusOf(r.Context(), h.postgres)
		if body.Postgres != "ok" {
			body.Status = "degraded"
		}
	}

	if h.redis != nil {
		body.Redis = pingStatusOf(r.Context(), h.redis)
		if body.Redis != "ok" {
			body.Status = "degraded"
		}
	}

	status := http.StatusOK
	if body.Status != "ok" {
		status = http.StatusServiceUnavailable
	}

	writeJSON(w, h.logger, status, body)
}

func pingStatusOf(ctx context.Context, p pingable) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := p.Ping(ctx); err != nil {
		return "down"
	}

	return "ok"
}
