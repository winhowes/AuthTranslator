package metrics

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type promPlugin struct{}

func (*promPlugin) OnRequest(string, *http.Request)                          {}
func (*promPlugin) OnResponse(string, string, *http.Request, *http.Response) {}
func (*promPlugin) WriteProm(w http.ResponseWriter)                          { fmt.Fprintln(w, "custom_metric 1") }

func TestMetricsHandlerEmpty(t *testing.T) {
	Reset()
	req := httptest.NewRequest(http.MethodGet, "/_at_internal/metrics", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req, "", "")

	if ct := rr.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4" {
		t.Fatalf("expected content type text/plain; version=0.0.4, got %s", ct)
	}
	if body := rr.Body.String(); body != "" {
		t.Fatalf("expected empty body, got %q", body)
	}
}

func TestMetricsHandlerOutput(t *testing.T) {
	Reset()
	IncRequest("foo")
	IncRequest("foo")
	IncRateLimit("foo")
	IncAuthFailure("foo")
	RecordStatus("foo", http.StatusOK)
	RecordStatus("bar", http.StatusTeapot)
	IncRequest("bar")
	RecordDuration("foo", 100*time.Millisecond)
	RecordDuration("foo", 200*time.Millisecond)
	RecordDuration("bar", 50*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/_at_internal/metrics", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req, "", "")

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
	Reset()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req, "admin", "secret")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing creds, got %d", rr.Code)
	}
	if rr.Header().Get("X-AT-Upstream-Error") != "false" {
		t.Fatal("missing auth error header")
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.SetBasicAuth("admin", "wrong")
	rr = httptest.NewRecorder()
	Handler(rr, req, "admin", "secret")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad creds, got %d", rr.Code)
	}
	if rr.Header().Get("X-AT-Upstream-Error") != "false" {
		t.Fatal("missing auth error header")
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.SetBasicAuth("admin", "secret")
	rr = httptest.NewRecorder()
	Handler(rr, req, "admin", "secret")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid creds, got %d", rr.Code)
	}
}

func TestCallerContext(t *testing.T) {
	ctx := WithCaller(context.Background(), "user1")
	if got := Caller(ctx); got != "user1" {
		t.Fatalf("expected caller user1, got %q", got)
	}
	if Caller(context.Background()) != "" {
		t.Fatal("expected empty caller for background context")
	}
}

func TestWritePromPlugins(t *testing.T) {
	Reset()
	mu.Lock()
	saved := plugins
	mu.Unlock()
	Reset()
	t.Cleanup(func() {
		mu.Lock()
		plugins = saved
		mu.Unlock()
	})

	Register(&promPlugin{})

	rr := httptest.NewRecorder()
	WriteProm(rr)
	if !strings.Contains(rr.Body.String(), "custom_metric 1") {
		t.Fatalf("custom metric missing: %s", rr.Body.String())
	}
}
