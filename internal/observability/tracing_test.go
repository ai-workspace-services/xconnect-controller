//go:build !no_apm

package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestResolveTracingProvider(t *testing.T) {
	t.Run("prefers OTel when both are set", func(t *testing.T) {
		t.Setenv("XCONNECT_CONFIG_PATH", "")
		t.Setenv("OBSERVABILITY_CONFIG_PATH", "")
		t.Setenv("CONFIG_PATH", "")
		t.Setenv("TRACING_PROVIDER", "")
		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://otel:4317")
		t.Setenv("OTEL_SDK_DISABLED", "")
		t.Setenv("DD_AGENT_HOST", "datakit-service.observability-sit.svc")
		t.Setenv("DD_TRACE_ENABLED", "true")
		if got := ResolveTracingProvider(); got != ProviderOTel {
			t.Fatalf("got %q, want %q", got, ProviderOTel)
		}
	})

	t.Run("defaults DD_TRACE_ENABLED to false even when DD_AGENT_HOST is set", func(t *testing.T) {
		t.Setenv("XCONNECT_CONFIG_PATH", "")
		t.Setenv("OBSERVABILITY_CONFIG_PATH", "")
		t.Setenv("CONFIG_PATH", "")
		t.Setenv("TRACING_PROVIDER", "")
		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
		t.Setenv("DD_AGENT_HOST", "datakit-service.observability-prod.svc")
		t.Setenv("DD_TRACE_ENABLED", "")
		if got := ResolveTracingProvider(); got != ProviderNone {
			t.Fatalf("got %q, want %q", got, ProviderNone)
		}
	})

	t.Run("enables ddtrace only when DD_TRACE_ENABLED=true and OTel absent or disabled", func(t *testing.T) {
		t.Setenv("XCONNECT_CONFIG_PATH", "")
		t.Setenv("OBSERVABILITY_CONFIG_PATH", "")
		t.Setenv("CONFIG_PATH", "")
		t.Setenv("TRACING_PROVIDER", "")
		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
		t.Setenv("DD_AGENT_HOST", "datakit-service.observability-prod.svc")
		t.Setenv("DD_TRACE_ENABLED", "true")
		if got := ResolveTracingProvider(); got != ProviderDDTrace {
			t.Fatalf("got %q, want %q", got, ProviderDDTrace)
		}

		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://otel:4317")
		t.Setenv("OTEL_SDK_DISABLED", "true")
		if got := ResolveTracingProvider(); got != ProviderDDTrace {
			t.Fatalf("got %q, want %q", got, ProviderDDTrace)
		}
	})

	t.Run("honors DD_TRACE_ENABLED=false even if TRACING_PROVIDER=ddtrace", func(t *testing.T) {
		t.Setenv("XCONNECT_CONFIG_PATH", "")
		t.Setenv("OBSERVABILITY_CONFIG_PATH", "")
		t.Setenv("CONFIG_PATH", "")
		t.Setenv("TRACING_PROVIDER", "ddtrace")
		t.Setenv("DD_AGENT_HOST", "datakit-service.observability-prod.svc")
		t.Setenv("DD_TRACE_ENABLED", "false")
		if got := ResolveTracingProvider(); got != ProviderNone {
			t.Fatalf("got %q, want %q", got, ProviderNone)
		}

		t.Setenv("DD_TRACE_ENABLED", "true")
		if got := ResolveTracingProvider(); got != ProviderDDTrace {
			t.Fatalf("got %q, want %q", got, ProviderDDTrace)
		}
	})
}

func TestTracingManagerConfigHotReload(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "observability.yaml")
	writeCfg := func(content string) {
		t.Helper()
		if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}

	t.Setenv("XCONNECT_CONFIG_PATH", cfgPath)
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	t.Setenv("DD_AGENT_HOST", "127.0.0.1")
	t.Setenv("DD_TRACE_AGENT_PORT", "19529")
	t.Setenv("DD_TRACE_ENABLED", "false")

	writeCfg("dd_trace_enabled: false\n")
	mgr, err := NewTracingManager(context.Background(), "xconnect-test")
	if err != nil {
		t.Fatalf("NewTracingManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Shutdown(context.Background()) })

	if got := mgr.Provider(); got != ProviderNone {
		t.Fatalf("initial provider = %q, want %q", got, ProviderNone)
	}

	writeCfg("observability:\n  dd_trace_enabled: true\n")
	changed, provider, err := mgr.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload enable ddtrace: %v", err)
	}
	if !changed || provider != ProviderDDTrace {
		t.Fatalf("after enable reload: changed=%v provider=%q, want true / %q", changed, provider, ProviderDDTrace)
	}

	changed, provider, err = mgr.Reload(context.Background())
	if err != nil || changed || provider != ProviderDDTrace {
		t.Fatalf("noop reload: changed=%v provider=%q err=%v", changed, provider, err)
	}

	writeCfg("observability:\n  dd_trace_enabled: false\n")
	changed, provider, err = mgr.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload disable ddtrace: %v", err)
	}
	if !changed || provider != ProviderNone {
		t.Fatalf("after disable reload: changed=%v provider=%q, want true / %q", changed, provider, ProviderNone)
	}
}

func TestDDTraceAgentAddr(t *testing.T) {
	t.Setenv("DD_AGENT_HOST", "datakit-service.observability-prod.svc")
	t.Setenv("DD_TRACE_AGENT_PORT", "")
	if got := DDTraceAgentAddr(); got != "datakit-service.observability-prod.svc:9529" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("DD_TRACE_AGENT_PORT", "19529")
	if got := DDTraceAgentAddr(); got != "datakit-service.observability-prod.svc:19529" {
		t.Fatalf("got %q", got)
	}
}

func TestWrapHTTPClientOTelPropagation(t *testing.T) {
	prevProvider := otel.GetTracerProvider()
	prevPropagator := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevProvider)
		otel.SetTextMapPropagator(prevPropagator)
	})

	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	var gotTraceparent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceparent = r.Header.Get("traceparent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, span := tp.Tracer("test").Start(context.Background(), "parent")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/.well-known/jwks.json", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := WrapHTTPClient(ProviderOTel, nil).Do(req)
	if err != nil {
		t.Fatalf("http do: %v", err)
	}
	resp.Body.Close()

	wantTraceID := span.SpanContext().TraceID().String()
	if !strings.Contains(gotTraceparent, "-"+wantTraceID+"-") {
		t.Fatalf("traceparent=%q does not include parent trace ID %q", gotTraceparent, wantTraceID)
	}

	plain := &http.Client{}
	if got := WrapHTTPClient(ProviderNone, plain); got != plain {
		t.Fatalf("expected ProviderNone to return original client unchanged")
	}
}
