package observability

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ProviderNone    = "none"
	ProviderOTel    = "otel"
	ProviderDDTrace = "ddtrace"
)

// TracingConfig defines runtime tracing controls across ENV and optional YAML/JSON config files.
// DDTraceEnabled strictly defaults to false unless explicitly enabled via config or ENV.
type TracingConfig struct {
	TracingProvider    string
	DDTraceEnabled     bool
	DDAgentHost        string
	DDTraceAgentPort   string
	DDService          string
	DDEnv              string
	DDVersion          string
	OTelSDKDisabled    bool
	OTelServiceName    string
	OTelEnvironment    string
	OTelProtocol       string
	OTelTracesEndpoint string
	OTelSamplerArg     string
}

type rawTracingFields struct {
	TracingProvider    *string `yaml:"tracing_provider" json:"tracing_provider"`
	DDTraceEnabled     *bool   `yaml:"dd_trace_enabled" json:"dd_trace_enabled"`
	DDAgentHost        *string `yaml:"dd_agent_host" json:"dd_agent_host"`
	DDTraceAgentPort   *string `yaml:"dd_trace_agent_port" json:"dd_trace_agent_port"`
	DDService          *string `yaml:"dd_service" json:"dd_service"`
	DDEnv              *string `yaml:"dd_env" json:"dd_env"`
	DDVersion          *string `yaml:"dd_version" json:"dd_version"`
	OTelSDKDisabled    *bool   `yaml:"otel_sdk_disabled" json:"otel_sdk_disabled"`
	OTelServiceName    *string `yaml:"otel_service_name" json:"otel_service_name"`
	OTelEnvironment    *string `yaml:"otel_environment" json:"otel_environment"`
	OTelProtocol       *string `yaml:"otel_exporter_otlp_protocol" json:"otel_exporter_otlp_protocol"`
	OTelTracesEndpoint *string `yaml:"otel_exporter_otlp_traces_endpoint" json:"otel_exporter_otlp_traces_endpoint"`
	OTelSamplerArg     *string `yaml:"otel_traces_sampler_arg" json:"otel_traces_sampler_arg"`
}

type rawTracingDocument struct {
	rawTracingFields `yaml:",inline"`
	Observability    *rawTracingFields `yaml:"observability" json:"observability"`
	Tracing          *rawTracingFields `yaml:"tracing" json:"tracing"`
}

// ConfigFilePath returns the configured observability config file path if any.
func ConfigFilePath() string {
	for _, key := range []string{"XCONNECT_CONFIG_PATH", "OBSERVABILITY_CONFIG_PATH", "CONFIG_PATH"} {
		if path := strings.TrimSpace(os.Getenv(key)); path != "" {
			return path
		}
	}
	return ""
}

// LoadTracingConfig loads tracing settings from ENV and overlays an optional YAML/JSON config file.
// Unset DD_TRACE_ENABLED defaults strictly to false.
func LoadTracingConfig() TracingConfig {
	cfg := TracingConfig{
		TracingProvider:    strings.ToLower(strings.TrimSpace(os.Getenv("TRACING_PROVIDER"))),
		DDTraceEnabled:     parseBoolStrict(os.Getenv("DD_TRACE_ENABLED")),
		DDAgentHost:        strings.TrimSpace(os.Getenv("DD_AGENT_HOST")),
		DDTraceAgentPort:   strings.TrimSpace(os.Getenv("DD_TRACE_AGENT_PORT")),
		DDService:          strings.TrimSpace(os.Getenv("DD_SERVICE")),
		DDEnv:              strings.TrimSpace(os.Getenv("DD_ENV")),
		DDVersion:          strings.TrimSpace(os.Getenv("DD_VERSION")),
		OTelSDKDisabled:    parseBoolStrict(os.Getenv("OTEL_SDK_DISABLED")),
		OTelServiceName:    strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")),
		OTelEnvironment:    strings.TrimSpace(os.Getenv("OTEL_ENVIRONMENT")),
		OTelProtocol:       strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")),
		OTelTracesEndpoint: strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")),
		OTelSamplerArg:     strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER_ARG")),
	}

	if path := ConfigFilePath(); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			cfg = overlayTracingBytes(cfg, data)
		}
	}
	if cfg.DDTraceAgentPort == "" {
		cfg.DDTraceAgentPort = "9529"
	}
	return cfg
}

func overlayTracingBytes(cfg TracingConfig, data []byte) TracingConfig {
	var doc rawTracingDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		// Try pure JSON fallback if YAML returned an error.
		if jsonErr := json.Unmarshal(data, &doc); jsonErr != nil {
			return cfg
		}
	}
	cfg = applyRawTracingFields(cfg, &doc.rawTracingFields)
	cfg = applyRawTracingFields(cfg, doc.Observability)
	cfg = applyRawTracingFields(cfg, doc.Tracing)
	return cfg
}

func applyRawTracingFields(cfg TracingConfig, raw *rawTracingFields) TracingConfig {
	if raw == nil {
		return cfg
	}
	if raw.TracingProvider != nil {
		cfg.TracingProvider = strings.ToLower(strings.TrimSpace(*raw.TracingProvider))
	}
	if raw.DDTraceEnabled != nil {
		cfg.DDTraceEnabled = *raw.DDTraceEnabled
	}
	if raw.DDAgentHost != nil {
		cfg.DDAgentHost = strings.TrimSpace(*raw.DDAgentHost)
	}
	if raw.DDTraceAgentPort != nil {
		cfg.DDTraceAgentPort = strings.TrimSpace(*raw.DDTraceAgentPort)
	}
	if raw.DDService != nil {
		cfg.DDService = strings.TrimSpace(*raw.DDService)
	}
	if raw.DDEnv != nil {
		cfg.DDEnv = strings.TrimSpace(*raw.DDEnv)
	}
	if raw.DDVersion != nil {
		cfg.DDVersion = strings.TrimSpace(*raw.DDVersion)
	}
	if raw.OTelSDKDisabled != nil {
		cfg.OTelSDKDisabled = *raw.OTelSDKDisabled
	}
	if raw.OTelServiceName != nil {
		cfg.OTelServiceName = strings.TrimSpace(*raw.OTelServiceName)
	}
	if raw.OTelEnvironment != nil {
		cfg.OTelEnvironment = strings.TrimSpace(*raw.OTelEnvironment)
	}
	if raw.OTelProtocol != nil {
		cfg.OTelProtocol = strings.TrimSpace(*raw.OTelProtocol)
	}
	if raw.OTelTracesEndpoint != nil {
		cfg.OTelTracesEndpoint = strings.TrimSpace(*raw.OTelTracesEndpoint)
	}
	if raw.OTelSamplerArg != nil {
		cfg.OTelSamplerArg = strings.TrimSpace(*raw.OTelSamplerArg)
	}
	return cfg
}

// ResolveTracingProviderFromConfig determines the active tracing backend with OTel-first
// precedence and strict DD_TRACE_ENABLED=false kill-switch semantics.
func ResolveTracingProviderFromConfig(cfg TracingConfig) string {
	switch strings.ToLower(strings.TrimSpace(cfg.TracingProvider)) {
	case ProviderOTel:
		if cfg.OTelSDKDisabled {
			return ProviderNone
		}
		return ProviderOTel
	case ProviderDDTrace:
		if !cfg.DDTraceEnabled {
			return ProviderNone
		}
		return ProviderDDTrace
	case ProviderNone:
		return ProviderNone
	}

	if cfg.OTelTracesEndpoint != "" && !cfg.OTelSDKDisabled {
		return ProviderOTel
	}

	if cfg.DDTraceEnabled && cfg.DDAgentHost != "" {
		return ProviderDDTrace
	}

	return ProviderNone
}

// DDTraceServiceName resolves the Datadog service name.
func DDTraceServiceName(defaultService string) string {
	return DDTraceServiceNameFromConfig(defaultService, LoadTracingConfig())
}

// DDTraceServiceNameFromConfig resolves the Datadog service name from a loaded config.
func DDTraceServiceNameFromConfig(defaultService string, cfg TracingConfig) string {
	return firstNonEmpty(cfg.DDService, cfg.OTelServiceName, defaultService)
}

// DDTraceAgentAddr builds host:port for DataKit DDTrace ingestion (default port 9529).
func DDTraceAgentAddr() string {
	return DDTraceAgentAddrFromConfig(LoadTracingConfig())
}

// DDTraceAgentAddrFromConfig builds host:port from a loaded config.
func DDTraceAgentAddrFromConfig(cfg TracingConfig) string {
	host := firstNonEmpty(cfg.DDAgentHost, "datakit-service.datakit.svc")
	port := strings.TrimSpace(cfg.DDTraceAgentPort)
	if port == "" {
		port = "9529"
	}
	return net.JoinHostPort(host, port)
}

// RuntimeLogAttrs returns structured log identity attributes.
func RuntimeLogAttrs(defaultService string) []any {
	cfg := LoadTracingConfig()
	serviceName := firstNonEmpty(cfg.DDService, cfg.OTelServiceName, defaultService)
	environment := firstNonEmpty(
		cfg.DDEnv,
		cfg.OTelEnvironment,
		os.Getenv("DEPLOY_ENV"),
		os.Getenv("RUNTIME_ENV"),
		os.Getenv("ENVIRONMENT"),
	)
	instance := firstNonEmpty(os.Getenv("OTEL_SERVICE_INSTANCE_ID"), os.Getenv("INSTANCE"), os.Getenv("HOSTNAME"), serviceName)
	return []any{"service.name", serviceName, "service_name", serviceName, "environment", environment, "instance", instance}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return "unknown"
}

func parseBoolStrict(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func configFileDigest(path string) ([32]byte, bool) {
	if path == "" {
		return [32]byte{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return [32]byte{}, false
		}
		return [32]byte{}, false
	}
	return sha256.Sum256(data), true
}

func resolveReloadInterval(fallback time.Duration) time.Duration {
	if fallback <= 0 {
		fallback = 5 * time.Second
	}
	if raw := strings.TrimSpace(os.Getenv("TRACING_RELOAD_INTERVAL")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}
