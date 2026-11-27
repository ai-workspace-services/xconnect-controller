//go:build !no_apm

package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestResolveTracingProvider(t *testing.T) {
	t.Run("prefers OTel when both are set", func(t *testing.T) {
		t.Setenv("TRACING_PROVIDER", "")
		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://otel:4317")
		t.Setenv("OTEL_SDK_DISABLED", "")
		t.Setenv("DD_AGENT_HOST", "datakit-service.observability-sit.svc")
		if got := ResolveTracingProvider(); got != ProviderOTel {
			t.Fatalf("got %q, want %q", got, ProviderOTel)
		}
	})

	t.Run("falls back to ddtrace when OTel is absent or disabled", func(t *testing.T) {
		t.Setenv("TRACING_PROVIDER", "")
		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
		t.Setenv("DD_AGENT_HOST", "datakit-service.observability-sit.svc")
		t.Setenv("DD_TRACE_ENABLED", "")
		if got := ResolveTracingProvider(); got != ProviderDDTrace {
			t.Fatalf("got %q, want %q", got, ProviderDDTrace)
		}

		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://otel:4317")
		t.Setenv("OTEL_SDK_DISABLED", "true")
		if got := ResolveTracingProvider(); got != ProviderDDTrace {
			t.Fatalf("got %q, want %q", got, ProviderDDTrace)
		}
	})

	t.Run("honors explicit override and defaults to none", func(t *testing.T) {
		t.Setenv("TRACING_PROVIDER", "ddtrace")
		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://otel:4317")
		t.Setenv("DD_AGENT_HOST", "datakit-service.observability-sit.svc")
		if got := ResolveTracingProvider(); got != ProviderDDTrace {
			t.Fatalf("got %q, want %q", got, ProviderDDTrace)
		}

		t.Setenv("TRACING_PROVIDER", "")
		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
		t.Setenv("DD_AGENT_HOST", "")
		if got := ResolveTracingProvider(); got != ProviderNone {
			t.Fatalf("got %q, want %q", got, ProviderNone)
		}
	})
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
