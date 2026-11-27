//go:build !no_apm

package observability

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
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

// ResolveTracingProvider selects the active tracing backend from config/ENV.
func ResolveTracingProvider() string {
	return ResolveTracingProviderFromConfig(LoadTracingConfig())
}

// ConfigureTracing initializes OTel or DDTrace according to ResolveTracingProvider.
func ConfigureTracing(ctx context.Context, defaultService string) (func(context.Context) error, string, error) {
	return configureTracingWithConfig(ctx, defaultService, LoadTracingConfig())
}

func configureTracingWithConfig(ctx context.Context, defaultService string, cfg TracingConfig) (func(context.Context) error, string, error) {
	provider := ResolveTracingProviderFromConfig(cfg)
	switch provider {
	case ProviderOTel:
		shutdown, err := ConfigureWithConfig(ctx, defaultService, cfg)
		if err != nil {
			return nil, ProviderNone, err
		}
		return shutdown, ProviderOTel, nil
	case ProviderDDTrace:
		opts := []tracer.StartOption{
			tracer.WithService(DDTraceServiceNameFromConfig(defaultService, cfg)),
			tracer.WithEnv(firstNonEmpty(
				cfg.DDEnv,
				cfg.OTelEnvironment,
				os.Getenv("DEPLOY_ENV"),
				os.Getenv("RUNTIME_ENV"),
				os.Getenv("ENVIRONMENT"),
				"unknown",
			)),
			tracer.WithAgentAddr(DDTraceAgentAddrFromConfig(cfg)),
		}
		if version := cfg.DDVersion; version != "" {
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

// TracingManager manages live tracing configuration with SIGHUP and config-file hot-reload.
type TracingManager struct {
	reloadMu       sync.Mutex
	mu             sync.RWMutex
	defaultService string
	currentCfg     TracingConfig
	provider       string
	middleware     gin.HandlerFunc
	shutdown       func(context.Context) error
}

// NewTracingManager initializes tracing from ENV/config file and returns a hot-reloadable manager.
func NewTracingManager(ctx context.Context, defaultService string) (*TracingManager, error) {
	cfg := LoadTracingConfig()
	shutdown, provider, err := configureTracingWithConfig(ctx, defaultService, cfg)
	if shutdown == nil {
		shutdown = func(context.Context) error { return nil }
	}
	return &TracingManager{
		defaultService: defaultService,
		currentCfg:     cfg,
		provider:       provider,
		middleware:     middlewareForConfig(provider, defaultService, cfg),
		shutdown:       shutdown,
	}, err
}

func middlewareForConfig(provider, defaultService string, cfg TracingConfig) gin.HandlerFunc {
	switch provider {
	case ProviderOTel:
		svc := firstNonEmpty(cfg.OTelServiceName, defaultService)
		return otelgin.Middleware(svc)
	case ProviderDDTrace:
		return gintrace.Middleware(DDTraceServiceNameFromConfig(defaultService, cfg))
	default:
		return nil
	}
}

// Provider returns the currently active tracing backend.
func (m *TracingManager) Provider() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.provider
}

// Reload re-reads ENV/config file and atomically swaps tracing middleware and providers on change.
func (m *TracingManager) Reload(ctx context.Context) (bool, string, error) {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	newCfg := LoadTracingConfig()
	m.mu.RLock()
	unchanged := newCfg == m.currentCfg
	curProvider := m.provider
	oldShutdown := m.shutdown
	m.mu.RUnlock()

	if unchanged {
		return false, curProvider, nil
	}

	if oldShutdown != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = oldShutdown(shutdownCtx)
		cancel()
	}

	newShutdown, newProvider, err := configureTracingWithConfig(ctx, m.defaultService, newCfg)
	if newShutdown == nil {
		newShutdown = func(context.Context) error { return nil }
	}
	newMiddleware := middlewareForConfig(newProvider, m.defaultService, newCfg)

	m.mu.Lock()
	m.currentCfg = newCfg
	m.provider = newProvider
	m.middleware = newMiddleware
	m.shutdown = newShutdown
	m.mu.Unlock()

	return true, newProvider, err
}

// Middleware returns a Gin handler that dispatches dynamically to the active tracing middleware.
func (m *TracingManager) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		m.mu.RLock()
		mw := m.middleware
		m.mu.RUnlock()
		if mw != nil {
			mw(c)
			return
		}
		c.Next()
	}
}

// WrapHTTPClient returns an HTTP client whose Transport dynamically follows the manager's active provider.
func (m *TracingManager) WrapHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	clone := *client
	base := clone.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	otelRT := wrapOTelTransport(base)
	ddRT := wrapDDTraceTransport(base)
	clone.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		switch m.Provider() {
		case ProviderOTel:
			return otelRT.RoundTrip(req)
		case ProviderDDTrace:
			return ddRT.RoundTrip(req)
		default:
			return base.RoundTrip(req)
		}
	})
	return &clone
}

// StartWatcher watches for SIGHUP signals and config file modifications until ctx is cancelled.
func (m *TracingManager) StartWatcher(ctx context.Context, interval time.Duration, onReload func(provider string, err error)) {
	pollEvery := resolveReloadInterval(interval)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	lastDigest, lastPresent := configFileDigest(ConfigFilePath())

	go func() {
		defer signal.Stop(sigCh)
		ticker := time.NewTicker(pollEvery)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
				if changed, provider, err := m.Reload(ctx); (changed || err != nil) && onReload != nil {
					onReload(provider, err)
				}
				lastDigest, lastPresent = configFileDigest(ConfigFilePath())
			case <-ticker.C:
				path := ConfigFilePath()
				if path == "" {
					continue
				}
				digest, present := configFileDigest(path)
				if present == lastPresent && digest == lastDigest {
					continue
				}
				lastDigest, lastPresent = digest, present
				if changed, provider, err := m.Reload(ctx); (changed || err != nil) && onReload != nil {
					onReload(provider, err)
				}
			}
		}
	}()
}

// Shutdown flushes and stops the currently active tracing provider.
func (m *TracingManager) Shutdown(ctx context.Context) error {
	m.mu.RLock()
	shutdown := m.shutdown
	m.mu.RUnlock()
	if shutdown == nil {
		return nil
	}
	return shutdown(ctx)
}
