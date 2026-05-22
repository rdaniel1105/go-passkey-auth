// Command server runs the passkey HTTP service.
package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib" // sql.Open("pgx", ...) for golang-migrate
	"github.com/redis/go-redis/v9"

	"github.com/rdaniel1105/go-passkey-auth/internal/api"
	"github.com/rdaniel1105/go-passkey-auth/internal/api/handler"
	"github.com/rdaniel1105/go-passkey-auth/internal/config"
	pgstore "github.com/rdaniel1105/go-passkey-auth/internal/store/postgres"
	redisstore "github.com/rdaniel1105/go-passkey-auth/internal/store/redis"
	pkwebauthn "github.com/rdaniel1105/go-passkey-auth/internal/webauthn"
)

// redisPinger adapts *redis.Client to the handler's pingable interface.
// go-redis's Ping returns a *StatusCmd, but the health handler wants
// Ping(ctx) error like pgxpool exposes.
type redisPinger struct {
	client *redis.Client
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := applyMigrations(cfg.DatabaseURL); err != nil {
		return err
	}

	pool, err := pgstore.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	redisClient, err := redisstore.NewClient(ctx, cfg.RedisURL)
	if err != nil {
		return err
	}
	defer redisClient.Close()

	wa, err := pkwebauthn.NewService(pkwebauthn.Config{
		RPID:            cfg.RPID,
		RPDisplayName:   cfg.RPDisplayName,
		RPOrigins:       cfg.RPOrigins,
		CeremonyTimeout: cfg.ChallengeTTL,
	})
	if err != nil {
		return err
	}

	userStore := pgstore.NewUserStore(pool)
	credentialStore := pgstore.NewCredentialStore(pool)
	sessionStore := redisstore.NewSessionStore(redisClient, cfg.SessionTTL)

	auth := handler.NewAuth(handler.AuthDeps{
		Logger:        logger,
		WebAuthn:      wa,
		Users:         userStore,
		Credentials:   credentialStore,
		Challenges:    redisstore.NewChallengeStore(redisClient, cfg.ChallengeTTL),
		Sessions:      sessionStore,
		Guests:        redisstore.NewGuestStore(redisClient, cfg.GuestTTL),
		SessionMaxAge: int(cfg.SessionTTL.Seconds()),
		GuestMaxAge:   int(cfg.GuestTTL.Seconds()),
	})

	user := handler.NewUser(handler.UserDeps{
		Logger:      logger,
		Users:       userStore,
		Credentials: credentialStore,
	})

	health := handler.NewHealth(handler.HealthDeps{
		Logger:   logger,
		Postgres: pool,
		Redis:    redisPinger{client: redisClient},
	})

	router := api.New(api.Deps{
		Logger:   logger,
		Auth:     auth,
		User:     user,
		Health:   health,
		Sessions: sessionStore,
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server starting", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-stop:
		logger.Info("server shutting down")
	case err := <-serverErr:
		if err != nil {
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return srv.Shutdown(shutdownCtx)
}

func (p redisPinger) Ping(ctx context.Context) error {
	return p.client.Ping(ctx).Err()
}

// applyMigrations runs all pending migrations against the database, using
// the embedded SQL files. Idempotent — already-applied migrations no-op.
func applyMigrations(dsn string) error {
	src, err := iofs.New(pgstore.MigrationsFS(), "migrations")
	if err != nil {
		return err
	}

	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	db, err := migratepg.WithInstance(sqlDB, &migratepg.Config{})
	if err != nil {
		return err
	}

	mig, err := migrate.NewWithInstance("iofs", src, "postgres", db)
	if err != nil {
		return err
	}

	if err := mig.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}

	return nil
}
