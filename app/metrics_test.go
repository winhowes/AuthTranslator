package main

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func resetMetrics() {
	requestCounts.Init()
	rateLimitCounts.Init()
	authFailureCounts.Init()
	upstreamStatusCounts.Init()
	durationHistsMu.Lock()
	durationHists = make(map[string]*histogram)
	durationHistsMu.Unlock()
	requestDurations.Init()
}

func TestMetricsHandlerEmpty(t *testing.T) {
	resetMetrics()
	req := httptest.NewRequest(http.MethodGet, "/_at_internal/metrics", nil)
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
	incAuthFailure("foo")
	recordStatus("foo", http.StatusOK)
	recordStatus("bar", http.StatusTeapot)
	incRequest("bar")
	recordDuration("foo", 100*time.Millisecond)
	recordDuration("foo", 200*time.Millisecond)
	recordDuration("bar", 50*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/_at_internal/metrics", nil)
	rr := httptest.NewRecorder()
	metricsHandler(rr, req)

	if ct := rr.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4" {
		t.Fatalf("expected content type text/plain; version=0.0.4, got %s", ct)
	}

	body := rr.Body.String()
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) < 26 {
		t.Fatalf("expected at least 26 metrics lines, got %d", len(lines))
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
	if !strings.Contains(body, `authtranslator_auth_failures_total{integration="foo"} 1`) {
		t.Fatal("missing foo auth failure metric")
	}
	if !strings.Contains(body, `authtranslator_upstream_responses_total{integration="foo",code="200"} 1`) {
		t.Fatal("missing foo status metric")
	}
	if !strings.Contains(body, `authtranslator_upstream_responses_total{integration="bar",code="418"} 1`) {
		t.Fatal("missing bar status metric")
	}
	if !strings.Contains(body, `authtranslator_request_duration_seconds_sum{integration="foo"}`) {
		t.Fatal("missing foo duration histogram")
	}
	if !strings.Contains(body, `authtranslator_request_duration_seconds_sum{integration="bar"}`) {
		t.Fatal("missing bar duration histogram")
	}
}

func TestMetricsHandlerAuth(t *testing.T) {
	resetMetrics()
	oldUser := *metricsUser
	oldPass := *metricsPass
	t.Cleanup(func() {
		flag.Set("metrics-user", oldUser)
		flag.Set("metrics-pass", oldPass)
	})

	if err := flag.Set("metrics-user", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := flag.Set("metrics-pass", "secret"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	metricsHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing creds, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.SetBasicAuth("admin", "wrong")
	rr = httptest.NewRecorder()
	metricsHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad creds, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.SetBasicAuth("admin", "secret")
	rr = httptest.NewRecorder()
	metricsHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid creds, got %d", rr.Code)
	}
}
