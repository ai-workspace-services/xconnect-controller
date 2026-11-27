package main

import "testing"

func TestHelpers(t *testing.T) {
	if !parseBool("true") || !parseBool("1") || parseBool("false") {
		t.Fatal("parseBool returned unexpected result")
	}
	if got := firstNonEmpty("", "  ", "fallback", "later"); got != "fallback" {
		t.Fatalf("firstNonEmpty = %q, want fallback", got)
	}
}
