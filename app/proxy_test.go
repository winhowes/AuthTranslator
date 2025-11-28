package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/token"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

type captureParams struct {
	ExpectHost string `json:"expect_host"`
}

type capturePlugin struct{}

func (capturePlugin) Name() string { return "test_capture" }

func (capturePlugin) ParseParams(params map[string]interface{}) (interface{}, error) {
	raw, ok := params["expect_host"].(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("expect_host must be provided")
	}
	return &captureParams{ExpectHost: raw}, nil
}

func (capturePlugin) AddAuth(_ context.Context, r *http.Request, params interface{}) error {
	cfg, ok := params.(*captureParams)
	if !ok {
		return fmt.Errorf("unexpected params type %T", params)
	}
	if r.URL.Host != cfg.ExpectHost {
		return fmt.Errorf("unexpected URL host %s", r.URL.Host)
	}
	if r.Host != cfg.ExpectHost {
		return fmt.Errorf("unexpected request host %s", r.Host)
	}
	if got := r.Header.Get("X-AT-Destination"); got != "" {
		return fmt.Errorf("X-AT-Destination should be stripped before AddAuth, got %q", got)
	}
	captureLastURL = r.URL.String()
	captureAddAuthCount++
	return nil
}

func (capturePlugin) RequiredParams() []string { return []string{"expect_host"} }

func (capturePlugin) OptionalParams() []string { return nil }

type identifyPlugin struct{}

func (identifyPlugin) Name() string { return "identify_test" }

func (identifyPlugin) ParseParams(map[string]interface{}) (interface{}, error) {
	return struct{}{}, nil
}

func (identifyPlugin) Authenticate(context.Context, *http.Request, interface{}) bool { return true }

func (identifyPlugin) Identify(*http.Request, interface{}) (string, bool) {
	return "known-caller", true
}

func (identifyPlugin) RequiredParams() []string { return nil }

func (identifyPlugin) OptionalParams() []string { return nil }

type failingPlugin struct{}

func (failingPlugin) Name() string { return "failing" }

func (failingPlugin) ParseParams(params map[string]interface{}) (interface{}, error) {
	return &struct{}{}, nil
}

func (failingPlugin) AddAuth(context.Context, *http.Request, interface{}) error {
	return fmt.Errorf("boom")
}

func (failingPlugin) RequiredParams() []string { return nil }

func (failingPlugin) OptionalParams() []string { return nil }

var (
	captureAddAuthCount int
	captureLastURL      string
)

func init() {
	authplugins.RegisterOutgoing(capturePlugin{})
	authplugins.RegisterOutgoing(failingPlugin{})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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

func TestProxyHandlerRetryAfterMinimumInLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	integ := Integration{Name: "rl-min-in", Destination: backend.URL, InRateLimit: 1, OutRateLimit: 10, RateLimitWindow: "100ms"}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() { integ.inLimiter.Stop(); integ.outLimiter.Stop() })

	req1 := httptest.NewRequest(http.MethodGet, "http://rl-min-in/", nil)
	req1.Host = "rl-min-in"
	req1.RemoteAddr = "4.5.6.7:1111"
	rr1 := httptest.NewRecorder()
	proxyHandler(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://rl-min-in/", nil)
	req2.Host = "rl-min-in"
	req2.RemoteAddr = "4.5.6.7:1111"
	rr2 := httptest.NewRecorder()
	proxyHandler(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit rejection, got %d", rr2.Code)
	}
	if got := rr2.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("expected minimum Retry-After of 1, got %q", got)
	}
	if rr2.Header().Get("X-AT-Error-Reason") != "caller rate limited" {
		t.Fatalf("unexpected error reason: %s", rr2.Header().Get("X-AT-Error-Reason"))
	}
}

func TestProxyHandlerRetryAfterMinimumOutLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	integ := Integration{Name: "rl-min-out", Destination: backend.URL, InRateLimit: 10, OutRateLimit: 1, RateLimitWindow: "100ms"}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() { integ.inLimiter.Stop(); integ.outLimiter.Stop() })

	req1 := httptest.NewRequest(http.MethodGet, "http://rl-min-out/", nil)
	req1.Host = "rl-min-out"
	rr1 := httptest.NewRecorder()
	proxyHandler(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://rl-min-out/", nil)
	req2.Host = "rl-min-out"
	rr2 := httptest.NewRecorder()
	proxyHandler(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit rejection, got %d", rr2.Code)
	}
	if got := rr2.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("expected minimum Retry-After of 1, got %q", got)
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

func TestProxyHandlerIdentifierSetsCallerID(t *testing.T) {
	authplugins.RegisterIncoming(identifyPlugin{})

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	integ := Integration{
		Name:         "identify",
		Destination:  backend.URL,
		InRateLimit:  2,
		OutRateLimit: 2,
		IncomingAuth: []AuthPluginConfig{{Type: "identify_test", Params: map[string]interface{}{}}},
	}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() { DeleteIntegration(integ.Name) })

	callers := []CallerConfig{{ID: "known-caller", Rules: []CallRule{{Path: "/", Methods: map[string]RequestConstraint{"GET": {}}}}}}
	if err := SetAllowlist(integ.Name, callers); err != nil {
		t.Fatalf("failed to set allowlist: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://identify/", nil)
	req.Host = "identify"
	rr := httptest.NewRecorder()
	proxyHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	integ.inLimiter.mu.Lock()
	count := integ.inLimiter.requests["known-caller"]
	integ.inLimiter.mu.Unlock()
	if count != 1 {
		t.Fatalf("expected rate limit key for caller, got %d", count)
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

func TestProxyHandlerWildcardMissingDestination(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

	integ := Integration{Name: "wild-missing", Destination: "http://*.example.com", InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() {
		integ.inLimiter.Stop()
		integ.outLimiter.Stop()
		DeleteIntegration("wild-missing")
	})

	req := httptest.NewRequest(http.MethodGet, "http://wild-missing/path", nil)
	req.Host = "wild-missing"
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if rr.Header().Get("X-AT-Error-Reason") != "invalid destination" {
		t.Fatalf("unexpected error reason: %s", rr.Header().Get("X-AT-Error-Reason"))
	}
}

func TestProxyHandlerWildcardHostMismatch(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

	integ := Integration{Name: "wild-mismatch", Destination: "http://*.example.com", InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() {
		integ.inLimiter.Stop()
		integ.outLimiter.Stop()
		DeleteIntegration("wild-mismatch")
	})

	req := httptest.NewRequest(http.MethodGet, "http://wild-mismatch/path", nil)
	req.Host = "wild-mismatch"
	req.Header.Set("X-AT-Destination", "http://example.com")
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if rr.Header().Get("X-AT-Error-Reason") != "invalid destination" {
		t.Fatalf("unexpected error reason: %s", rr.Header().Get("X-AT-Error-Reason"))
	}
}

func TestProxyHandlerWildcardSuccess(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

	integ := Integration{Name: "wild-success", Destination: "http://*.example.com/base?static=1", InRateLimit: 1, OutRateLimit: 1}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() {
		integ.inLimiter.Stop()
		integ.outLimiter.Stop()
		DeleteIntegration("wild-success")
	})

	called := false
	integ.proxy.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		if req.URL.Host != "foo.example.com" {
			t.Fatalf("unexpected upstream host: %s", req.URL.Host)
		}
		if req.Host != "foo.example.com" {
			t.Fatalf("unexpected request host: %s", req.Host)
		}
		if req.URL.Path != "/base/test" {
			t.Fatalf("unexpected upstream path: %s", req.URL.Path)
		}
		if req.URL.RawQuery != "static=1&foo=bar" {
			t.Fatalf("unexpected query: %s", req.URL.RawQuery)
		}
		if req.Header.Get("X-AT-Destination") != "" {
			t.Fatal("X-AT-Destination header should be stripped before proxying")
		}
		resp := &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}
		return resp, nil
	})

	req := httptest.NewRequest(http.MethodGet, "http://wild-success/test?foo=bar", nil)
	req.Host = "wild-success"
	req.Header.Set("X-AT-Destination", "http://foo.example.com")
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if !called {
		t.Fatal("expected transport to be invoked")
	}
}

func TestProxyHandlerWildcardAddAuthSeesResolvedDestination(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

	captureAddAuthCount = 0
	captureLastURL = ""

	integ := Integration{
		Name:         "wild-auth",
		Destination:  "http://*.example.com/base?static=1",
		InRateLimit:  1,
		OutRateLimit: 1,
		OutgoingAuth: []AuthPluginConfig{{
			Type:   "test_capture",
			Params: map[string]interface{}{"expect_host": "foo.example.com"},
		}},
	}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() {
		integ.inLimiter.Stop()
		integ.outLimiter.Stop()
		DeleteIntegration("wild-auth")
	})

	integ.proxy.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp := &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}
		return resp, nil
	})

	req := httptest.NewRequest(http.MethodGet, "http://wild-auth/test?foo=bar", nil)
	req.Host = "wild-auth"
	req.Header.Set("X-AT-Destination", "http://foo.example.com")
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if captureAddAuthCount != 1 {
		t.Fatalf("expected AddAuth to be called once, got %d", captureAddAuthCount)
	}
	if captureLastURL != "http://foo.example.com/base/test?static=1&foo=bar" {
		t.Fatalf("unexpected URL seen by AddAuth: %s", captureLastURL)
	}
}

func TestProxyHandlerOutgoingAuthError(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

	integ := Integration{
		Name:         "fail-auth",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
		OutgoingAuth: []AuthPluginConfig{{Type: "failing", Params: map[string]interface{}{}}},
	}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() {
		integ.inLimiter.Stop()
		integ.outLimiter.Stop()
		DeleteIntegration("fail-auth")
	})

	req := httptest.NewRequest(http.MethodGet, "http://fail-auth/", nil)
	req.Host = "fail-auth"
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if rr.Header().Get("X-AT-Error-Reason") != "authentication failed" {
		t.Fatalf("unexpected error reason %q", rr.Header().Get("X-AT-Error-Reason"))
	}
}

func TestProxyHandlerWildcardPreservesEncodedPath(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

	integ := Integration{
		Name:         "wild-encoded",
		Destination:  "http://*.example.com/base",
		InRateLimit:  1,
		OutRateLimit: 1,
	}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	t.Cleanup(func() {
		integ.inLimiter.Stop()
		integ.outLimiter.Stop()
		DeleteIntegration("wild-encoded")
	})

	called := false
	integ.proxy.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		if req.URL.Path != "/base/foo/bar" {
			t.Fatalf("unexpected path: %s", req.URL.Path)
		}
		if req.URL.RawPath != "/base/foo%2Fbar" {
			t.Fatalf("unexpected raw path: %s", req.URL.RawPath)
		}
		resp := &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}
		return resp, nil
	})

	req := httptest.NewRequest(http.MethodGet, "http://wild-encoded/foo%2Fbar?foo=bar", nil)
	req.Host = "wild-encoded"
	req.Header.Set("X-AT-Destination", "http://foo.example.com")
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if !called {
		t.Fatal("expected transport to be invoked")
	}
}
