package durationrecorder

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/winhowes/AuthTranslator/app/metrics"
)

func TestDurationRecorder(t *testing.T) {
	dr := &durationRecorder{}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	dr.OnRequest("foo", req)
	time.Sleep(10 * time.Millisecond)
	dr.OnResponse("foo", "", req, &http.Response{})

	rr := httptest.NewRecorder()
	metrics.Handler(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil), "", "")
	body := rr.Body.String()
	if !strings.Contains(body, `authtranslator_request_duration_seconds_sum{integration="foo"}`) {
		t.Fatalf("duration histogram missing: %s", body)
	}
	if !strings.Contains(body, `authtranslator_request_duration_seconds_count{integration="foo"} 1`) {
		t.Fatalf("duration count missing: %s", body)
	}
}
