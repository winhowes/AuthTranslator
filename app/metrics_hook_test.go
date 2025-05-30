package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/winhowes/AuthTranslator/app/metrics"
)

type hookPlugin struct {
	req  int
	resp int
}

func (h *hookPlugin) OnRequest(integ string, r *http.Request) {
	h.req++
}

func (h *hookPlugin) OnResponse(integ string, r *http.Request, resp *http.Response) {
	h.resp++
}

func TestMetricsHooks(t *testing.T) {
	metrics.Reset()

	hp := &hookPlugin{}
	metrics.Register(hp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	integ := Integration{Name: "metric", Destination: srv.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("add integration: %v", err)
	}
	t.Cleanup(func() {
		integ.inLimiter.Stop()
		integ.outLimiter.Stop()
	})

	req := httptest.NewRequest(http.MethodGet, "http://metric/foo", nil)
	req.Host = "metric"
	rr := httptest.NewRecorder()
	proxyHandler(rr, req)

	if hp.req != 1 {
		t.Fatalf("expected request hook 1, got %d", hp.req)
	}
	if hp.resp != 1 {
		t.Fatalf("expected response hook 1, got %d", hp.resp)
	}
}
