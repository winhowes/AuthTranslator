package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func resetMetrics() {
	requestCounts.Init()
	rateLimitCounts.Init()
	durationHistsMu.Lock()
	durationHists = make(map[string]*histogram)
	durationHistsMu.Unlock()
	requestDurations.Init()
}

func TestMetricsHandlerEmpty(t *testing.T) {
	resetMetrics()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	metricsHandler(rr, req)

	if ct := rr.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4" {
		t.Fatalf("expected content type text/plain; version=0.0.4, got %s", ct)
	}
	if body := rr.Body.String(); body != "" {
		t.Fatalf("expected empty body, got %q", body)
	}
}

func TestMetricsHandlerOutput(t *testing.T) {
	resetMetrics()
	incRequest("foo")
	incRequest("foo")
	incRateLimit("foo")
	incRequest("bar")
	recordDuration("foo", 100*time.Millisecond)
	recordDuration("foo", 200*time.Millisecond)
	recordDuration("bar", 50*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	metricsHandler(rr, req)

	if ct := rr.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4" {
		t.Fatalf("expected content type text/plain; version=0.0.4, got %s", ct)
	}

	body := rr.Body.String()
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) < 23 {
		t.Fatalf("expected at least 23 metrics lines, got %d", len(lines))
	}
	if !strings.Contains(body, `authtranslator_requests_total{integration="foo"} 2`) {
		t.Fatal("missing foo request metric")
	}
	if !strings.Contains(body, `authtranslator_rate_limit_events_total{integration="foo"} 1`) {
		t.Fatal("missing foo rate limit metric")
	}
	if !strings.Contains(body, `authtranslator_requests_total{integration="bar"} 1`) {
		t.Fatal("missing bar request metric")
	}
	if !strings.Contains(body, `authtranslator_request_duration_seconds_sum{integration="foo"}`) {
		t.Fatal("missing foo duration histogram")
	}
	if !strings.Contains(body, `authtranslator_request_duration_seconds_sum{integration="bar"}`) {
		t.Fatal("missing bar duration histogram")
	}
}
