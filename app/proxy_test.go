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

func TestProxyHandlerDisableXAtInt(t *testing.T) {
	*disableXATInt = true
	defer func() { *disableXATInt = false }()

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

	headerInt := Integration{Name: "dis-header", Destination: srvHeader.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&headerInt); err != nil {
		t.Fatalf("failed to add header integration: %v", err)
	}
	t.Cleanup(func() {
		headerInt.inLimiter.Stop()
		headerInt.outLimiter.Stop()
	})

	hostInt := Integration{Name: "dis-host", Destination: srvHost.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&hostInt); err != nil {
		t.Fatalf("failed to add host integration: %v", err)
	}
	t.Cleanup(func() {
		hostInt.inLimiter.Stop()
		hostInt.outLimiter.Stop()
	})

	req := httptest.NewRequest(http.MethodGet, "http://dis-host/example", nil)
	req.Host = "dis-host"
	req.Header.Set("X-AT-Int", "dis-header")
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if !srvHostHit || srvHeaderHit {
		t.Fatal("request should be routed to host integration")
	}
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected status from host integration, got %d", rr.Code)
	}
}

func TestProxyHandlerXAtIntHostAllowed(t *testing.T) {
	*xAtIntHost = "allowedhost"
	defer func() { *xAtIntHost = "" }()

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

	headerInt := Integration{Name: "restr-header", Destination: srvHeader.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&headerInt); err != nil {
		t.Fatalf("failed to add header integration: %v", err)
	}
	t.Cleanup(func() {
		headerInt.inLimiter.Stop()
		headerInt.outLimiter.Stop()
	})

	hostInt := Integration{Name: "allowedhost", Destination: srvHost.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&hostInt); err != nil {
		t.Fatalf("failed to add host integration: %v", err)
	}
	t.Cleanup(func() {
		hostInt.inLimiter.Stop()
		hostInt.outLimiter.Stop()
	})

	req := httptest.NewRequest(http.MethodGet, "http://allowedhost/test", nil)
	req.Host = "allowedhost"
	req.Header.Set("X-AT-Int", "restr-header")
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if !srvHeaderHit || srvHostHit {
		t.Fatal("request should be routed to header integration")
	}
	if rr.Code != http.StatusTeapot {
		t.Fatalf("expected status from header integration, got %d", rr.Code)
	}
}

func TestProxyHandlerXAtIntHostMismatch(t *testing.T) {
	*xAtIntHost = "allowedhost"
	defer func() { *xAtIntHost = "" }()

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

	headerInt := Integration{Name: "restr2-header", Destination: srvHeader.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&headerInt); err != nil {
		t.Fatalf("failed to add header integration: %v", err)
	}
	t.Cleanup(func() {
		headerInt.inLimiter.Stop()
		headerInt.outLimiter.Stop()
	})

	hostInt := Integration{Name: "otherhost", Destination: srvHost.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&hostInt); err != nil {
		t.Fatalf("failed to add host integration: %v", err)
	}
	t.Cleanup(func() {
		hostInt.inLimiter.Stop()
		hostInt.outLimiter.Stop()
	})

	req := httptest.NewRequest(http.MethodGet, "http://otherhost/test", nil)
	req.Host = "otherhost"
	req.Header.Set("X-AT-Int", "restr2-header")
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if !srvHostHit || srvHeaderHit {
		t.Fatal("request should be routed to host integration")
	}
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected status from host integration, got %d", rr.Code)
	}
}
