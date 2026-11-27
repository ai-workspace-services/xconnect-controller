//go:build !no_apm

package observability

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	sqltrace "github.com/DataDog/dd-trace-go/contrib/database/sql/v2"
	gintrace "github.com/DataDog/dd-trace-go/contrib/gin-gonic/gin/v2"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/XSAM/otelsql"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/stdlib"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const (
	ProviderNone    = "none"
	ProviderOTel    = "otel"
	ProviderDDTrace = "ddtrace"
)

// ResolveTracingProvider selects the active tracing backend with OTel-first
// mutual exclusion so HTTP and SQL clients are not double-instrumented.
func ResolveTracingProvider() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRACING_PROVIDER"))) {
	case ProviderOTel:
		return ProviderOTel
	case ProviderDDTrace:
		return ProviderDDTrace
	case ProviderNone:
		return ProviderNone
	}

	if strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")) != "" &&
		!strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED")), "true") {
		return ProviderOTel
	}

	if strings.TrimSpace(os.Getenv("DD_AGENT_HOST")) != "" &&
		!strings.EqualFold(strings.TrimSpace(os.Getenv("DD_TRACE_ENABLED")), "false") {
		return ProviderDDTrace
	}

	return ProviderNone
}

// DDTraceServiceName resolves the Datadog service name.
func DDTraceServiceName(defaultService string) string {
	return firstNonEmpty(os.Getenv("DD_SERVICE"), os.Getenv("OTEL_SERVICE_NAME"), defaultService)
}

// DDTraceAgentAddr builds host:port for DataKit DDTrace ingestion (default port 9529).
func DDTraceAgentAddr() string {
	host := firstNonEmpty(os.Getenv("DD_AGENT_HOST"), "datakit-service.datakit.svc")
	port := strings.TrimSpace(os.Getenv("DD_TRACE_AGENT_PORT"))
	if port == "" {
		port = "9529"
	}
	return net.JoinHostPort(host, port)
}

// ConfigureTracing initializes OTel or DDTrace according to ResolveTracingProvider.
func ConfigureTracing(ctx context.Context, defaultService string) (func(context.Context) error, string, error) {
	provider := ResolveTracingProvider()
	switch provider {
	case ProviderOTel:
		shutdown, err := Configure(ctx, defaultService)
		if err != nil {
			return nil, ProviderNone, err
		}
		return shutdown, ProviderOTel, nil
	case ProviderDDTrace:
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
			return nil, ProviderNone, err
		}
		return func(context.Context) error {
			tracer.Stop()
			return nil
		}, ProviderDDTrace, nil
	default:
		return func(context.Context) error { return nil }, ProviderNone, nil
	}
}

// DDTraceSpanAttrs returns trace/span IDs from an active DDTrace span when present.
func DDTraceSpanAttrs(ctx context.Context, defaultService string) []any {
	span, ok := tracer.SpanFromContext(ctx)
	if !ok {
		return nil
	}
	sc := span.Context()
	if sc == nil || sc.TraceID() == "" {
		return nil
	}
	attrs := RuntimeLogAttrs(defaultService)
	return append(attrs,
		"trace_id", sc.TraceID(),
		"span_id", sc.SpanID(),
		"dd.trace_id", sc.TraceID(),
		"dd.span_id", sc.SpanID(),
	)
}

var registerDDPGXOnce sync.Once

// OpenPostgres opens a PostgreSQL connection pool instrumented with OTel or DDTrace.
func OpenPostgres(dsn string) (*sql.DB, error) {
	switch ResolveTracingProvider() {
	case ProviderOTel:
		return otelsql.Open("pgx", dsn)
	case ProviderDDTrace:
		registerDDPGXOnce.Do(func() {
			sqltrace.Register("dd-pgx", &stdlib.Driver{}, sqltrace.WithService("postgres"))
		})
		return sqltrace.Open("dd-pgx", dsn)
	default:
		return sql.Open("pgx", dsn)
	}
}

// GinMiddleware returns Gin middleware for the active tracing provider.
func GinMiddleware(provider, defaultService string) gin.HandlerFunc {
	switch provider {
	case ProviderOTel:
		return otelgin.Middleware(defaultService)
	case ProviderDDTrace:
		return gintrace.Middleware(DDTraceServiceName(defaultService))
	default:
		return func(c *gin.Context) { c.Next() }
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// WrapHTTPClient instruments an HTTP client with client spans and trace header propagation.
func WrapHTTPClient(provider string, client *http.Client) *http.Client {
	if provider != ProviderOTel && provider != ProviderDDTrace {
		return client
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	clone := *client
	base := clone.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	if provider == ProviderOTel {
		clone.Transport = wrapOTelTransport(base)
		return &clone
	}
	clone.Transport = wrapDDTraceTransport(base)
	return &clone
}

func wrapOTelTransport(base http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		spanName := fmt.Sprintf("%s %s%s", req.Method, req.URL.Host, req.URL.Path)
		ctx, span := otel.Tracer("xconnect-controller/http-client").Start(
			req.Context(),
			spanName,
			trace.WithSpanKind(trace.SpanKindClient),
			trace.WithAttributes(
				attribute.String("http.request.method", req.Method),
				attribute.String("url.full", req.URL.String()),
			),
		)
		defer span.End()

		outReq := req.Clone(ctx)
		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(outReq.Header))

		resp, err := base.RoundTrip(outReq)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))
		if resp.StatusCode >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, http.StatusText(resp.StatusCode))
		}
		return resp, nil
	})
}

func wrapDDTraceTransport(base http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		span, ctx := tracer.StartSpanFromContext(
			req.Context(),
			"http.request",
			tracer.ResourceName(req.Method+" "+req.URL.Path),
			tracer.Tag("http.method", req.Method),
			tracer.Tag("http.url", req.URL.String()),
			tracer.SpanType("http"),
		)
		outReq := req.Clone(ctx)
		_ = tracer.Inject(span.Context(), tracer.HTTPHeadersCarrier(outReq.Header))

		resp, err := base.RoundTrip(outReq)
		if err != nil {
			span.Finish(tracer.WithError(err))
			return nil, err
		}
		span.SetTag("http.status_code", resp.StatusCode)
		if resp.StatusCode >= http.StatusInternalServerError {
			span.Finish(tracer.WithError(fmt.Errorf("http status %d", resp.StatusCode)))
		} else {
			span.Finish()
		}
		return resp, nil
	})
}
