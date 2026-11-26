//go:build !no_apm

package observability

import (
	"log/slog"
	"net"
	"os"
	"strings"

	gintrace "github.com/DataDog/dd-trace-go/contrib/gin-gonic/gin/v2"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/gin-gonic/gin"
)

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// DDTraceEnabled returns true when DD_AGENT_HOST is configured and tracing is not disabled.
func DDTraceEnabled() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("TRACING_PROVIDER")), "none") {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("DD_TRACE_ENABLED")), "false") {
		return false
	}
	return strings.TrimSpace(os.Getenv("DD_AGENT_HOST")) != ""
}

// DDTraceServiceName resolves the Datadog service name.
func DDTraceServiceName(defaultService string) string {
	return firstNonEmpty(os.Getenv("DD_SERVICE"), os.Getenv("OTEL_SERVICE_NAME"), defaultService)
}

// DDTraceAgentAddr builds host:port for DataKit DDTrace ingestion (default port 9529).
func DDTraceAgentAddr() string {
	host := firstNonEmpty(os.Getenv("DD_AGENT_HOST"), "datakit-service.datakit.svc")
	port := firstNonEmpty(os.Getenv("DD_TRACE_AGENT_PORT"), "9529")
	return net.JoinHostPort(host, port)
}

// ConfigureDDTrace initializes dd-trace-go when DD_AGENT_HOST is configured.
func ConfigureDDTrace(defaultService string) (func(), bool) {
	if !DDTraceEnabled() {
		return func() {}, false
	}
	opts := []tracer.StartOption{
		tracer.WithService(DDTraceServiceName(defaultService)),
		tracer.WithEnv(firstNonEmpty(
			os.Getenv("DD_ENV"),
			os.Getenv("OTEL_ENVIRONMENT"),
			os.Getenv("DEPLOY_ENV"),
			os.Getenv("RUNTIME_ENV"),
			os.Getenv("ENVIRONMENT"),
			"unknown",
		)),
		tracer.WithAgentAddr(DDTraceAgentAddr()),
	}
	if version := strings.TrimSpace(os.Getenv("DD_VERSION")); version != "" {
		opts = append(opts, tracer.WithServiceVersion(version))
	}
	if err := tracer.Start(opts...); err != nil {
		slog.Warn("ddtrace disabled", "err", err)
		return func() {}, false
	}
	return tracer.Stop, true
}

// GinMiddleware returns Gin middleware for dd-trace-go.
func GinMiddleware(defaultService string) gin.HandlerFunc {
	return gintrace.Middleware(DDTraceServiceName(defaultService))
}
