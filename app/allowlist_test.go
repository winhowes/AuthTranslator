package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/winhowes/AuthTranslator/app/authplugins/basic"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/google_oidc"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/token"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestAllowlist(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	t.Setenv("TOK", "secret")
	integ := Integration{
		Name:         "allowlist",
		Destination:  backend.URL,
		InRateLimit:  10,
		OutRateLimit: 10,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "X-Auth"}}},
	}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	SetAllowlist("allowlist", []CallerConfig{
		{ID: "*", Rules: []CallRule{{Path: "/allowed", Methods: map[string]RequestConstraint{"GET": {}}}}},
	})
	t.Cleanup(func() {
		integ.inLimiter.Stop()
		integ.outLimiter.Stop()
	})

	req := httptest.NewRequest(http.MethodGet, "http://allowlist/allowed", nil)
	req.Host = "allowlist"
	req.Header.Set("X-Auth", "secret")
	rr := httptest.NewRecorder()
	proxyHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://allowlist/forbidden", nil)
	req2.Host = "allowlist"
	req2.Header.Set("X-Auth", "secret")
	rr2 := httptest.NewRecorder()
	proxyHandler(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr2.Code)
	}
}

func TestSetAllowlistIndexing(t *testing.T) {
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	SetAllowlist("idx", []CallerConfig{{ID: "id"}, {}})

	allowlists.RLock()
	callers := allowlists.m["idx"]
	_, haveID := callers["id"]
	_, haveWildcard := callers["*"]
	allowlists.RUnlock()

	if !haveID || !haveWildcard {
		t.Fatalf("allowlist indexing failed: id=%v wildcard=%v", haveID, haveWildcard)
	}
}

func TestFindConstraintWildcard(t *testing.T) {
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	SetAllowlist("fc", []CallerConfig{
		{ID: "abc", Rules: []CallRule{{Path: "/abc", Methods: map[string]RequestConstraint{"GET": {}}}}},
		{Rules: []CallRule{{Path: "/wild", Methods: map[string]RequestConstraint{"GET": {}}}}},
	})

	integ := &Integration{Name: "fc"}

	if _, ok := findConstraint(integ, "abc", "/abc", http.MethodGet); !ok {
		t.Fatal("expected specific constraint")
	}
	if _, ok := findConstraint(integ, "xyz", "/wild", http.MethodGet); !ok {
		t.Fatal("expected wildcard constraint")
	}
	if _, ok := findConstraint(integ, "xyz", "/none", http.MethodGet); ok {
		t.Fatal("unexpected match for unknown path")
	}
}
