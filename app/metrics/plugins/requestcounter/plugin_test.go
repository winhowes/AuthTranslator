package requestcounter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/winhowes/AuthTranslator/app/metrics"
)

func TestRequestCounter(t *testing.T) {
	rc := &requestCounter{}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	rc.OnRequest("foo", req)

	rr := httptest.NewRecorder()
	metrics.Handler(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil), "", "")
	if !strings.Contains(rr.Body.String(), `authtranslator_requests_total{integration="foo"} 1`) {
		t.Fatalf("request metric missing: %s", rr.Body.String())
	}
}

func TestRequestCounterOnResponse(t *testing.T) {
	rc := &requestCounter{}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	resp := &http.Response{}
	rc.OnResponse("foo", "", req, resp)
	// Nothing to assert - function is a no-op, just ensure it doesn't panic
}
