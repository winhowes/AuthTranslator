package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/winhowes/AuthTranslator/app/metrics"
)

func TestHealthz(t *testing.T) {
	prev := metrics.LastReloadTime.Value()
	metrics.LastReloadTime.Set("2023-09-01T00:00:00Z")
	t.Cleanup(func() { metrics.LastReloadTime.Set(prev) })

	req := httptest.NewRequest(http.MethodGet, "/_at_internal/healthz", nil)
	rr := httptest.NewRecorder()
	healthzHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("X-Last-Reload"); got != "2023-09-01T00:00:00Z" {
		t.Fatalf("unexpected X-Last-Reload header %q", got)
	}
}
