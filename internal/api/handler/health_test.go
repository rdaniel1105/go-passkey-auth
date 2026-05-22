package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakePingable struct {
	err error
}

func (p fakePingable) Ping(_ context.Context) error { return p.err }

func newHealth(postgres, redis pingable) *HealthHandler {
	return NewHealth(HealthDeps{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Postgres: postgres,
		Redis:    redis,
	})
}

func TestLive_AlwaysOK(t *testing.T) {
	c := require.New(t)

	h := newHealth(nil, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	h.Live(rr, req)

	c.Equal(http.StatusOK, rr.Code)

	var body map[string]string
	c.NoError(json.Unmarshal(rr.Body.Bytes(), &body))
	c.Equal("ok", body["status"])
}

func TestReady_AllUp(t *testing.T) {
	c := require.New(t)

	h := newHealth(fakePingable{}, fakePingable{})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	h.Ready(rr, req)

	c.Equal(http.StatusOK, rr.Code)

	var body readyResponse
	c.NoError(json.Unmarshal(rr.Body.Bytes(), &body))
	c.Equal("ok", body.Status)
	c.Equal("ok", body.Postgres)
	c.Equal("ok", body.Redis)
}

func TestReady_PostgresDown(t *testing.T) {
	c := require.New(t)

	h := newHealth(fakePingable{err: errors.New("conn refused")}, fakePingable{})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	h.Ready(rr, req)

	c.Equal(http.StatusServiceUnavailable, rr.Code)

	var body readyResponse
	c.NoError(json.Unmarshal(rr.Body.Bytes(), &body))
	c.Equal("degraded", body.Status)
	c.Equal("down", body.Postgres)
	c.Equal("ok", body.Redis)
}

func TestReady_RedisDown(t *testing.T) {
	c := require.New(t)

	h := newHealth(fakePingable{}, fakePingable{err: errors.New("conn refused")})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	h.Ready(rr, req)

	c.Equal(http.StatusServiceUnavailable, rr.Code)

	var body readyResponse
	c.NoError(json.Unmarshal(rr.Body.Bytes(), &body))
	c.Equal("degraded", body.Status)
	c.Equal("ok", body.Postgres)
	c.Equal("down", body.Redis)
}

func TestReady_NilDeps_Skipped(t *testing.T) {
	c := require.New(t)

	// No dependencies wired: probe is still OK; subsystems omitted.
	h := newHealth(nil, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	h.Ready(rr, req)

	c.Equal(http.StatusOK, rr.Code)

	var body readyResponse
	c.NoError(json.Unmarshal(rr.Body.Bytes(), &body))
	c.Equal("ok", body.Status)
	c.Empty(body.Postgres)
	c.Empty(body.Redis)
}
