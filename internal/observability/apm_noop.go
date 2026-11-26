//go:build no_apm

package observability

import (
	"net"
	"os"
	"strings"

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

// DDTraceEnabled always returns false when compiled with -tags no_apm.
func DDTraceEnabled() bool {
	return false
}

// DDTraceServiceName resolves the service name from environment or default.
func DDTraceServiceName(defaultService string) string {
	return firstNonEmpty(os.Getenv("DD_SERVICE"), os.Getenv("OTEL_SERVICE_NAME"), defaultService)
}

// DDTraceAgentAddr builds host:port for DataKit DDTrace ingestion.
func DDTraceAgentAddr() string {
	host := firstNonEmpty(os.Getenv("DD_AGENT_HOST"), "datakit-service.datakit.svc")
	port := firstNonEmpty(os.Getenv("DD_TRACE_AGENT_PORT"), "9529")
	return net.JoinHostPort(host, port)
}

// ConfigureDDTrace is a no-op when compiled with -tags no_apm.
func ConfigureDDTrace(string) (func(), bool) {
	return func() {}, false
}

// GinMiddleware returns a pass-through middleware when compiled with -tags no_apm.
func GinMiddleware(string) gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}
