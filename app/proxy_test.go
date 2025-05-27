package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyHandlerPrefersHeader(t *testing.T) {
	srvHeaderHit := false
	srvHeader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srvHeaderHit = true
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srvHeader.Close()

	srvHostHit := false
	srvHost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srvHostHit = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srvHost.Close()

	headerInt := Integration{Name: "header", Destination: srvHeader.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&headerInt); err != nil {
		t.Fatalf("failed to add header integration: %v", err)
	}
	t.Cleanup(func() {
		headerInt.inLimiter.Stop()
		headerInt.outLimiter.Stop()
	})

	hostInt := Integration{Name: "host", Destination: srvHost.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&hostInt); err != nil {
		t.Fatalf("failed to add host integration: %v", err)
	}
	t.Cleanup(func() {
		hostInt.inLimiter.Stop()
		hostInt.outLimiter.Stop()
	})

	req := httptest.NewRequest(http.MethodGet, "http://host/example", nil)
	req.Host = "host"
	req.Header.Set("X-AT-Int", "header")
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if !srvHeaderHit || srvHostHit {
		t.Fatal("request should be routed to header integration")
	}
	if rr.Code != http.StatusTeapot {
		t.Fatalf("expected status from header integration, got %d", rr.Code)
	}
}

func TestProxyHandlerUsesHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	hostInt := Integration{Name: "hostonly", Destination: srv.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&hostInt); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() {
		hostInt.inLimiter.Stop()
		hostInt.outLimiter.Stop()
	})

	req := httptest.NewRequest(http.MethodGet, "http://hostonly/test", nil)
	req.Host = "hostonly"
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected status from host integration, got %d", rr.Code)
	}
}
