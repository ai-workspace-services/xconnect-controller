package observability

import "testing"

func TestDDTraceEnabledAndAddr(t *testing.T) {
	t.Setenv("TRACING_PROVIDER", "")
	t.Setenv("DD_TRACE_ENABLED", "")
	t.Setenv("DD_AGENT_HOST", "")
	if DDTraceEnabled() {
		t.Fatal("expected DDTraceEnabled to be false when DD_AGENT_HOST is unset")
	}

	t.Setenv("DD_AGENT_HOST", "datakit-service.observability-sit.svc")
	t.Setenv("DD_TRACE_AGENT_PORT", "")
	if !DDTraceEnabled() {
		t.Fatal("expected DDTraceEnabled to be true when DD_AGENT_HOST is set")
	}
	if got := DDTraceAgentAddr(); got != "datakit-service.observability-sit.svc:9529" {
		t.Fatalf("got %q", got)
	}

	t.Setenv("TRACING_PROVIDER", "none")
	if DDTraceEnabled() {
		t.Fatal("expected TRACING_PROVIDER=none to disable ddtrace")
	}
}
