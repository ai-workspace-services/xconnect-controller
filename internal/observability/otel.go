//go:build !no_apm

package observability

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Configure enables OTLP tracing only when an endpoint is configured.
func Configure(ctx context.Context, defaultService string) (func(context.Context) error, error) {
	return ConfigureWithConfig(ctx, defaultService, LoadTracingConfig())
}

// ConfigureWithConfig initializes OTLP tracing and W3C propagation from TracingConfig.
func ConfigureWithConfig(ctx context.Context, defaultService string, cfg TracingConfig) (func(context.Context) error, error) {
	endpoint := strings.TrimSpace(cfg.OTelTracesEndpoint)
	if endpoint == "" || cfg.OTelSDKDisabled {
		return func(context.Context) error { return nil }, nil
	}

	ratio := 0.05
	if raw := strings.TrimSpace(cfg.OTelSamplerArg); raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		if err != nil || parsed < 0 || parsed > 1 {
			return nil, fmt.Errorf("invalid OTEL_TRACES_SAMPLER_ARG %q", raw)
		}
		ratio = parsed
	}
	serviceName := strings.TrimSpace(cfg.OTelServiceName)
	if serviceName == "" {
		serviceName = defaultService
	}
	environment := firstNonEmpty(
		cfg.OTelEnvironment,
		os.Getenv("DEPLOY_ENV"),
		os.Getenv("RUNTIME_ENV"),
		os.Getenv("ENVIRONMENT"),
		"unknown",
	)
	instance := firstNonEmpty(
		os.Getenv("OTEL_SERVICE_INSTANCE_ID"),
		os.Getenv("INSTANCE"),
		os.Getenv("HOSTNAME"),
		serviceName,
	)

	var exporter sdktrace.SpanExporter
	var err error
	if strings.EqualFold(cfg.OTelProtocol, "grpc") {
		exporter, err = otlptracegrpc.New(ctx, otlptracegrpc.WithEndpointURL(endpoint))
	} else {
		exporter, err = otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint))
	}
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
		sdktrace.WithResource(resource.NewWithAttributes("",
			attribute.String("service.name", serviceName),
			attribute.String("service.instance.id", instance),
			attribute.String("deployment.environment.name", environment),
			attribute.String("deployment.environment", environment),
			attribute.String("environment", environment),
			attribute.String("instance", instance),
		)),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	return provider.Shutdown, nil
}

// TraceLogAttrs returns stable correlation fields for structured request logs.
func TraceLogAttrs(ctx context.Context) []any {
	spanContext := trace.SpanContextFromContext(ctx)
	if !spanContext.IsValid() {
		return DDTraceSpanAttrs(ctx, "web-saas-xconnect-controller")
	}
	attrs := RuntimeLogAttrs("web-saas-xconnect-controller")
	return append(attrs,
		"trace_id", spanContext.TraceID().String(),
		"span_id", spanContext.SpanID().String(),
	)
}
