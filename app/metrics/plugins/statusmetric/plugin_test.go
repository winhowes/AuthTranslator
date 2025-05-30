package statusmetric

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/winhowes/AuthTranslator/app/metrics"
)

func TestStatusMetric(t *testing.T) {
	sm := &statusMetric{}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	resp := &http.Response{StatusCode: http.StatusTeapot}
	sm.OnResponse("foo", "", req, resp)

	rr := httptest.NewRecorder()
	metrics.Handler(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil), "", "")
	if !strings.Contains(rr.Body.String(), `authtranslator_upstream_responses_total{integration="foo",code="418"} 1`) {
		t.Fatalf("status metric missing: %s", rr.Body.String())
	}
}

func TestStatusMetricOnRequest(t *testing.T) {
	sm := &statusMetric{}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	sm.OnRequest("foo", req)
	// No metrics are recorded on request; ensure no panic
}
