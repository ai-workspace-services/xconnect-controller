//go:build no_apm

package observability

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// ResolveTracingProvider always returns ProviderNone when compiled with -tags no_apm.
func ResolveTracingProvider() string {
	return ProviderNone
}

// Configure is a no-op when compiled with -tags no_apm.
func Configure(context.Context, string) (func(context.Context) error, error) {
	return func(context.Context) error { return nil }, nil
}

// ConfigureWithConfig is a no-op when compiled with -tags no_apm.
func ConfigureWithConfig(context.Context, string, TracingConfig) (func(context.Context) error, error) {
	return func(context.Context) error { return nil }, nil
}

// ConfigureTracing is a no-op when compiled with -tags no_apm.
func ConfigureTracing(context.Context, string) (func(context.Context) error, string, error) {
	return func(context.Context) error { return nil }, ProviderNone, nil
}

// TraceLogAttrs returns runtime log attributes when compiled with -tags no_apm.
func TraceLogAttrs(context.Context) []any {
	return RuntimeLogAttrs("web-saas-xconnect-controller")
}

// DDTraceSpanAttrs returns nil when compiled with -tags no_apm.
func DDTraceSpanAttrs(context.Context, string) []any {
	return nil
}

// OpenPostgres opens a plain pgx connection pool when compiled with -tags no_apm.
func OpenPostgres(dsn string) (*sql.DB, error) {
	return sql.Open("pgx", dsn)
}

// GinMiddleware returns a pass-through middleware when compiled with -tags no_apm.
func GinMiddleware(string, string) gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

// WrapHTTPClient returns the HTTP client unchanged when compiled with -tags no_apm.
func WrapHTTPClient(_ string, client *http.Client) *http.Client {
	return client
}

// TracingManager is a no-op manager when compiled with -tags no_apm.
type TracingManager struct{}

// NewTracingManager returns a no-op TracingManager when compiled with -tags no_apm.
func NewTracingManager(context.Context, string) (*TracingManager, error) {
	return &TracingManager{}, nil
}

// Provider always returns ProviderNone when compiled with -tags no_apm.
func (*TracingManager) Provider() string { return ProviderNone }

// Reload is a no-op when compiled with -tags no_apm.
func (*TracingManager) Reload(context.Context) (bool, string, error) {
	return false, ProviderNone, nil
}

// Middleware returns a pass-through handler when compiled with -tags no_apm.
func (*TracingManager) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

// WrapHTTPClient returns the HTTP client unchanged when compiled with -tags no_apm.
func (*TracingManager) WrapHTTPClient(client *http.Client) *http.Client {
	return client
}

// StartWatcher is a no-op when compiled with -tags no_apm.
func (*TracingManager) StartWatcher(context.Context, time.Duration, func(string, error)) {}

// Shutdown is a no-op when compiled with -tags no_apm.
func (*TracingManager) Shutdown(context.Context) error { return nil }
