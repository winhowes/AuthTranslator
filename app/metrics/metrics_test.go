package metrics

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type promPlugin struct{}

func (*promPlugin) OnRequest(string, *http.Request)                          {}
func (*promPlugin) OnResponse(string, string, *http.Request, *http.Response) {}
func (*promPlugin) WriteProm(w http.ResponseWriter)                          { fmt.Fprintln(w, "custom_metric 1") }

type blockingResponseWriter struct {
	header  http.Header
	blockCh <-chan struct{}
	started chan<- struct{}
	once    sync.Once
}

func (w *blockingResponseWriter) Header() http.Header { return w.header }

func (w *blockingResponseWriter) Write(b []byte) (int, error) {
	w.once.Do(func() {
		close(w.started)
	})
	<-w.blockCh
	return len(b), nil
}

func (w *blockingResponseWriter) WriteHeader(_ int) {}

func TestMetricsHandlerEmpty(t *testing.T) {
	Reset()
	req := httptest.NewRequest(http.MethodGet, "/_at_internal/metrics", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req, "", "")

	if ct := rr.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4" {
		t.Fatalf("expected content type text/plain; version=0.0.4, got %s", ct)
	}

	body := rr.Body.String()
	for _, line := range []string{
		"# TYPE authtranslator_requests_total counter",
		"# TYPE authtranslator_upstream_roundtrip_duration_seconds histogram",
		"# TYPE authtranslator_end_to_end_duration_seconds histogram",
		"# TYPE authtranslator_pre_proxy_duration_seconds histogram",
		"# TYPE authtranslator_response_processing_duration_seconds histogram",
		"# TYPE authtranslator_rate_limit_events_total counter",
		"# TYPE authtranslator_auth_failures_total counter",
		"# TYPE authtranslator_internal_responses_total counter",
		"# TYPE authtranslator_upstream_responses_total counter",
	} {
		if !strings.Contains(body, line) {
			t.Fatalf("missing metric type line %q in %q", line, body)
		}
	}
	if strings.Contains(body, `{integration="`) {
		t.Fatalf("expected no metric samples, got %q", body)
	}
}

func TestMetricsHandlerOutput(t *testing.T) {
	Reset()
	IncRequest("foo")
	IncRequest("foo")
	IncRateLimit("foo")
	IncAuthFailure("foo")
	IncInternalResponse("foo", http.StatusUnauthorized, "incoming_auth_failure")
	RecordStatus("foo", http.StatusOK)
	RecordStatus("bar", http.StatusTeapot)
	IncRequest("bar")
	RecordUpstreamRoundtripDuration("foo", 100*time.Millisecond)
	RecordUpstreamRoundtripDuration("foo", 200*time.Millisecond)
	RecordUpstreamRoundtripDuration("bar", 50*time.Millisecond)
	RecordEndToEndDuration("foo", 250*time.Millisecond)
	RecordEndToEndDuration("bar", 75*time.Millisecond)
	RecordPreProxyDuration("foo", 20*time.Millisecond)
	RecordPreProxyDuration("bar", 10*time.Millisecond)
	RecordResponseProcessingDuration("foo", 15*time.Millisecond)
	RecordResponseProcessingDuration("bar", 5*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/_at_internal/metrics", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req, "", "")

	if ct := rr.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4" {
		t.Fatalf("expected content type text/plain; version=0.0.4, got %s", ct)
	}

	body := rr.Body.String()
	for _, line := range []string{
		"# TYPE authtranslator_requests_total counter",
		"# TYPE authtranslator_upstream_roundtrip_duration_seconds histogram",
		"# TYPE authtranslator_end_to_end_duration_seconds histogram",
		"# TYPE authtranslator_pre_proxy_duration_seconds histogram",
		"# TYPE authtranslator_response_processing_duration_seconds histogram",
		"# TYPE authtranslator_rate_limit_events_total counter",
		"# TYPE authtranslator_auth_failures_total counter",
		"# TYPE authtranslator_internal_responses_total counter",
		"# TYPE authtranslator_upstream_responses_total counter",
	} {
		if !strings.Contains(body, line) {
			t.Fatalf("missing metric type line %q in %q", line, body)
		}
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
	if !strings.Contains(body, `authtranslator_internal_responses_total{integration="foo",code="401",reason="incoming_auth_failure"} 1`) {
		t.Fatal("missing foo internal response metric")
	}
	if !strings.Contains(body, `authtranslator_upstream_responses_total{integration="foo",code="200"} 1`) {
		t.Fatal("missing foo status metric")
	}
	if !strings.Contains(body, `authtranslator_upstream_responses_total{integration="bar",code="418"} 1`) {
		t.Fatal("missing bar status metric")
	}
	if !strings.Contains(body, `authtranslator_upstream_roundtrip_duration_seconds_sum{integration="foo"}`) {
		t.Fatal("missing foo upstream duration histogram")
	}
	if !strings.Contains(body, `authtranslator_upstream_roundtrip_duration_seconds_sum{integration="bar"}`) {
		t.Fatal("missing bar upstream duration histogram")
	}
	if !strings.Contains(body, `authtranslator_end_to_end_duration_seconds_sum{integration="foo"}`) {
		t.Fatal("missing foo end-to-end duration histogram")
	}
	if !strings.Contains(body, `authtranslator_pre_proxy_duration_seconds_sum{integration="foo"}`) {
		t.Fatal("missing foo pre-proxy duration histogram")
	}
	if !strings.Contains(body, `authtranslator_response_processing_duration_seconds_sum{integration="foo"}`) {
		t.Fatal("missing foo response processing duration histogram")
	}
}

func TestMetricsHandlerOutputWithPunctuation(t *testing.T) {
	Reset()

	dotName := "with.dot"
	underscoreName := "with_underscore"

	IncRequest(dotName)
	RecordUpstreamRoundtripDuration(dotName, 150*time.Millisecond)
	RecordStatus(dotName, http.StatusAccepted)
	IncInternalResponse(dotName, http.StatusBadRequest, "invalid_destination")

	RecordStatus(underscoreName, http.StatusBadGateway)

	req := httptest.NewRequest(http.MethodGet, "/_at_internal/metrics", nil)
	rr := httptest.NewRecorder()
	Handler(rr, req, "", "")

	body := rr.Body.String()
	if !strings.Contains(body, fmt.Sprintf(`authtranslator_requests_total{integration=%q} 1`, dotName)) {
		t.Fatalf("missing request counter for %s: %s", dotName, body)
	}
	if !strings.Contains(body, fmt.Sprintf(`authtranslator_upstream_roundtrip_duration_seconds_sum{integration=%q}`, dotName)) {
		t.Fatalf("missing duration histogram for %s: %s", dotName, body)
	}
	if !strings.Contains(body, fmt.Sprintf(`authtranslator_upstream_responses_total{integration=%q,code=%q} 1`, dotName, "202")) {
		t.Fatalf("missing status metric for %s: %s", dotName, body)
	}
	if !strings.Contains(body, fmt.Sprintf(`authtranslator_internal_responses_total{integration=%q,code=%q,reason=%q} 1`, dotName, "400", "invalid_destination")) {
		t.Fatalf("missing internal response metric for %s: %s", dotName, body)
	}
	if !strings.Contains(body, fmt.Sprintf(`authtranslator_upstream_responses_total{integration=%q,code=%q} 1`, underscoreName, "502")) {
		t.Fatalf("missing status metric for %s: %s", underscoreName, body)
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
	if ct := rr.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("unexpected content type %s", ct)
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
	if ct := rr.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("unexpected content type %s", ct)
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

func TestWritePromSkipsMalformedUpstreamKeys(t *testing.T) {
	Reset()

	upstreamStatusCounts.Add("badkey", 3)
	internalResponseCounts.Add("stillbad", 2)
	RecordStatus("foo", http.StatusOK)
	IncInternalResponse("foo", http.StatusBadRequest, "invalid_destination")

	rr := httptest.NewRecorder()
	WriteProm(rr)

	body := rr.Body.String()
	if strings.Contains(body, "badkey") {
		t.Fatalf("expected malformed upstream key to be ignored, got %q", body)
	}
	if strings.Contains(body, "stillbad") {
		t.Fatalf("expected malformed internal response key to be ignored, got %q", body)
	}
	if !strings.Contains(body, `authtranslator_upstream_responses_total{integration="foo",code="200"} 1`) {
		t.Fatalf("missing valid upstream status metric: %s", body)
	}
	if !strings.Contains(body, `authtranslator_internal_responses_total{integration="foo",code="400",reason="invalid_destination"} 1`) {
		t.Fatalf("missing valid internal response metric: %s", body)
	}
}

func TestWritePromDoesNotBlockRecordDurationForOtherIntegrations(t *testing.T) {
	Reset()
	RecordUpstreamRoundtripDuration("one", 100*time.Millisecond)

	blockCh := make(chan struct{})
	started := make(chan struct{})
	bw := &blockingResponseWriter{
		header:  make(http.Header),
		blockCh: blockCh,
		started: started,
	}

	done := make(chan struct{})
	go func() {
		WriteProm(bw)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("WriteProm did not start writing")
	}

	recordDone := make(chan struct{})
	go func() {
		RecordUpstreamRoundtripDuration("two", 50*time.Millisecond)
		close(recordDone)
	}()

	select {
	case <-recordDone:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("RecordUpstreamRoundtripDuration blocked while metrics response writer was blocked")
	}

	close(blockCh)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WriteProm did not finish after unblocking writer")
	}
}
