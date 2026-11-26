package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ai-workspace-services/xconnect-controller/internal/auth"
	"github.com/ai-workspace-services/xconnect-controller/internal/httpapi"
	"github.com/ai-workspace-services/xconnect-controller/internal/observability"
	"github.com/ai-workspace-services/xconnect-controller/internal/overlay"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	stopTracing, tracingProvider, traceErr := observability.ConfigureTracing(ctx, "web-saas-xconnect-controller")
	if traceErr != nil {
		logger.Warn("tracing disabled", "err", traceErr)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := stopTracing(shutdownCtx); err != nil {
			logger.Warn("tracing shutdown failed", "err", err)
		}
	}()

	db, err := openDatabase()
	if err != nil {
		logger.Error("failed to initialize database", "err", err)
		os.Exit(1)
	}

	overlayCfg, err := overlay.ConfigFromEnv()
	if err != nil {
		logger.Error("invalid overlay configuration", "err", err)
		os.Exit(1)
	}
	overlayCfg.SchemaManaged = parseBool(os.Getenv("XCONNECT_SCHEMA_MANAGED"))
	overlayService, err := overlay.NewService(db, overlayCfg)
	if err != nil {
		logger.Error("failed to initialize overlay service", "err", err)
		os.Exit(1)
	}
	overlayService.StartSessionCleanup(ctx, overlay.DefaultSessionCleanupInterval, overlay.DefaultEnrollmentRetention, func(deleted int64, cleanupErr error) {
		if cleanupErr != nil {
			logger.Warn("overlay enrollment session cleanup failed", "err", cleanupErr)
			return
		}
		if deleted > 0 {
			logger.Info("pruned expired overlay enrollment sessions", "deleted", deleted)
		}
	})

	var userReader auth.UserReader
	if db.Migrator().HasTable("users") {
		userReader = auth.NewGORMUserReader(db)
	}
	verifier := auth.NewVerifier(auth.VerifierConfigFromEnv(userReader))

	var middlewares []gin.HandlerFunc
	if tracingProvider != observability.ProviderNone {
		middlewares = append(middlewares, observability.GinMiddleware(tracingProvider, "web-saas-xconnect-controller"))
	}

	router := httpapi.NewRouter(httpapi.Server{
		Overlay:     overlayService,
		Verifier:    verifier,
		Middlewares: middlewares,
		DBHealth: func(probeCtx context.Context) error {
			sqlDB, sqlErr := db.DB()
			if sqlErr != nil {
				return sqlErr
			}
			return sqlDB.PingContext(probeCtx)
		},
	})

	addr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	if addr == "" {
		port := strings.TrimSpace(os.Getenv("PORT"))
		if port == "" {
			port = "8080"
		}
		addr = ":" + port
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("xconnect-controller listening", "addr", addr, "schema_managed", overlayCfg.SchemaManaged)
		if serveErr := srv.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error("http server error", "err", serveErr)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("graceful shutdown timed out", "err", err)
	}
}

func openDatabase() (*gorm.DB, error) {
	if dsn := strings.TrimSpace(os.Getenv("DATABASE_URL")); dsn != "" {
		if strings.HasPrefix(dsn, "sqlite://") || strings.HasPrefix(dsn, "file:") || strings.HasSuffix(dsn, ".db") {
			return gorm.Open(sqlite.Open(strings.TrimPrefix(dsn, "sqlite://")), &gorm.Config{})
		}
		sqlDB, err := observability.OpenPostgres(dsn)
		if err != nil {
			return nil, err
		}
		return gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{})
	}
	host := strings.TrimSpace(os.Getenv("DB_HOST"))
	if host == "" {
		return gorm.Open(sqlite.Open("file:xconnect_controller.db?cache=shared"), &gorm.Config{})
	}
	port := strings.TrimSpace(os.Getenv("DB_PORT"))
	if port == "" {
		port = "5432"
	}
	user := firstNonEmpty(os.Getenv("POSTGRES_USER"), os.Getenv("DB_USER"), "postgres")
	pass := firstNonEmpty(os.Getenv("POSTGRES_PASSWORD"), os.Getenv("DB_PASSWORD"))
	name := firstNonEmpty(os.Getenv("DB_NAME"), "account")
	sslMode := firstNonEmpty(os.Getenv("DB_SSLMODE"), "disable")
	pgURL := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, pass),
		Host:   fmt.Sprintf("%s:%s", host, port),
		Path:   name,
	}
	q := pgURL.Query()
	q.Set("sslmode", sslMode)
	pgURL.RawQuery = q.Encode()
	sqlDB, err := observability.OpenPostgres(pgURL.String())
	if err != nil {
		return nil, err
	}
	return gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{})
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func parseBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
