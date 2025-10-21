package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/token"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestProxyHandlerPrefersHeader(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

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
	if rr.Header().Get("X-AT-Upstream-Error") != "true" {
		t.Fatal("missing upstream error header")
	}
}

func TestProxyHandlerUsesHost(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

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

func TestProxyHandlerHostCaseInsensitive(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	hostInt := Integration{Name: "casehost", Destination: srv.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&hostInt); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() {
		hostInt.inLimiter.Stop()
		hostInt.outLimiter.Stop()
	})

	req := httptest.NewRequest(http.MethodGet, "http://CASEHOST/test", nil)
	req.Host = "CASEHOST"
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected status from host integration, got %d", rr.Code)
	}
}

func TestProxyHandlerDisableXAtInt(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

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

func TestProxyHandlerDenylistBlocks(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer backend.Close()

	integ := Integration{Name: "deny", Destination: backend.URL, InRateLimit: 0, OutRateLimit: 0}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() {
		integ.inLimiter.Stop()
		integ.outLimiter.Stop()
	})

	if err := SetDenylist("deny", []DenylistCaller{{
		ID: "*",
		Rules: []CallRule{{
			Path: "/blocked",
			Methods: map[string]RequestConstraint{
				"GET": {Headers: map[string][]string{"X-Block": {"yes"}}},
			},
		}},
	}}); err != nil {
		t.Fatalf("failed to set denylist: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://deny/blocked", nil)
	req.Host = "deny"
	req.Header.Set("X-Block", "yes")
	rr := httptest.NewRecorder()
	proxyHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://deny/other", nil)
	req2.Host = "deny"
	rr2 := httptest.NewRecorder()
	proxyHandler(rr2, req2)
	if rr2.Code != http.StatusCreated {
		t.Fatalf("expected upstream status, got %d", rr2.Code)
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

func TestProxyHandlerRateLimiterUsesIP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	integ := Integration{Name: "rl-ip", Destination: backend.URL, InRateLimit: 1, OutRateLimit: 10, RateLimitWindow: "2s"}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() {
		integ.inLimiter.Stop()
		integ.outLimiter.Stop()
	})

	req1 := httptest.NewRequest(http.MethodGet, "http://rl-ip/", nil)
	req1.Host = "rl-ip"
	req1.RemoteAddr = "1.2.3.4:1234"
	rr1 := httptest.NewRecorder()
	proxyHandler(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://rl-ip/", nil)
	req2.Host = "rl-ip"
	req2.RemoteAddr = "1.2.3.4:5678"
	rr2 := httptest.NewRecorder()
	proxyHandler(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit rejection, got %d", rr2.Code)
	}
	if rr2.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
	if rr2.Header().Get("X-AT-Upstream-Error") != "false" {
		t.Fatal("missing auth error header")
	}
	if rr2.Header().Get("X-AT-Error-Reason") != "caller rate limited" {
		t.Fatalf("unexpected error reason: %s", rr2.Header().Get("X-AT-Error-Reason"))
	}
}

func TestProxyHandlerRateLimiterNoPort(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	integ := Integration{Name: "rl-np", Destination: backend.URL, InRateLimit: 1, OutRateLimit: 10, RateLimitWindow: "2s"}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() { integ.inLimiter.Stop(); integ.outLimiter.Stop() })

	req1 := httptest.NewRequest(http.MethodGet, "http://rl-np/", nil)
	req1.Host = "rl-np"
	req1.RemoteAddr = "1.2.3.4"
	rr1 := httptest.NewRecorder()
	proxyHandler(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://rl-np/", nil)
	req2.Host = "rl-np"
	req2.RemoteAddr = "1.2.3.4"
	rr2 := httptest.NewRecorder()
	proxyHandler(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit rejection, got %d", rr2.Code)
	}
}

func TestProxyHandlerRetryAfterOutLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	integ := Integration{Name: "rl-out", Destination: backend.URL, InRateLimit: 10, OutRateLimit: 1, RateLimitWindow: "2s"}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() { integ.inLimiter.Stop(); integ.outLimiter.Stop() })

	req1 := httptest.NewRequest(http.MethodGet, "http://rl-out/", nil)
	req1.Host = "rl-out"
	rr1 := httptest.NewRecorder()
	proxyHandler(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://rl-out/", nil)
	req2.Host = "rl-out"
	rr2 := httptest.NewRecorder()
	proxyHandler(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit rejection, got %d", rr2.Code)
	}
	if rr2.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
	if rr2.Header().Get("X-AT-Upstream-Error") != "false" {
		t.Fatal("missing auth error header")
	}
	if rr2.Header().Get("X-AT-Error-Reason") != "integration rate limited" {
		t.Fatalf("unexpected error reason: %s", rr2.Header().Get("X-AT-Error-Reason"))
	}
}

func TestProxyHandlerNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://missing/", nil)
	req.Host = "missing"
	rr := httptest.NewRecorder()
	proxyHandler(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
	if rr.Header().Get("X-AT-Upstream-Error") != "false" {
		t.Fatal("missing auth error header")
	}
	if rr.Header().Get("X-AT-Error-Reason") != "integration not found" {
		t.Fatalf("unexpected error reason: %s", rr.Header().Get("X-AT-Error-Reason"))
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("unexpected content type %s", ct)
	}
}

func TestProxyHandlerAuthFailure(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	t.Setenv("TOK", "secret")
	integ := Integration{
		Name:         "authfail",
		Destination:  backend.URL,
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "X-Auth"}}},
	}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() { integ.inLimiter.Stop(); integ.outLimiter.Stop() })

	req := httptest.NewRequest(http.MethodGet, "http://authfail/", nil)
	req.Host = "authfail"
	req.Header.Set("X-Auth", "wrong")
	rr := httptest.NewRecorder()
	proxyHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if rr.Header().Get("X-AT-Upstream-Error") != "false" {
		t.Fatal("missing auth error header")
	}
	if rr.Header().Get("X-AT-Error-Reason") != "authentication failed" {
		t.Fatalf("unexpected error reason: %s", rr.Header().Get("X-AT-Error-Reason"))
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("unexpected content type %s", ct)
	}
}

func TestProxyHandlerBadGateway(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	integ := Integration{Name: "badgw", Destination: backend.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	integrations.Lock()
	integrations.m["badgw"].proxy = nil
	integrations.Unlock()
	t.Cleanup(func() { integ.inLimiter.Stop(); integ.outLimiter.Stop() })

	req := httptest.NewRequest(http.MethodGet, "http://badgw/", nil)
	req.Host = "badgw"
	rr := httptest.NewRecorder()
	proxyHandler(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rr.Code)
	}
	if rr.Header().Get("X-AT-Upstream-Error") != "false" {
		t.Fatal("missing auth error header")
	}
	if rr.Header().Get("X-AT-Error-Reason") != "no proxy configured" {
		t.Fatalf("unexpected error reason: %s", rr.Header().Get("X-AT-Error-Reason"))
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("unexpected content type %s", ct)
	}
}

func TestProxyHandlerRewritesHost(t *testing.T) {
	var upstreamHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	integ := Integration{Name: "hostrewrite", Destination: srv.URL, InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() { integ.inLimiter.Stop(); integ.outLimiter.Stop() })

	req := httptest.NewRequest(http.MethodGet, "http://hostrewrite/", nil)
	req.Host = "hostrewrite"
	rr := httptest.NewRecorder()
	proxyHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	u, _ := url.Parse(srv.URL)
	if upstreamHost != u.Host {
		t.Fatalf("expected host %s, got %s", u.Host, upstreamHost)
	}
}
