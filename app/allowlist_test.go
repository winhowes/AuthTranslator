package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/basic"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/google_oidc"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/token"
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
	if err := SetAllowlist("allowlist", []CallerConfig{
		{ID: "*", Rules: []CallRule{{Path: "/allowed", Methods: map[string]RequestConstraint{"GET": {}}}}},
	}); err != nil {
		t.Fatalf("failed to set allowlist: %v", err)
	}
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
	if rr2.Header().Get("X-AT-Upstream-Error") != "false" {
		t.Fatal("missing auth error header")
	}
}

func TestSetAllowlistIndexing(t *testing.T) {
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	if err := SetAllowlist("idx", []CallerConfig{{ID: "id"}, {}}); err != nil {
		t.Fatalf("failed to set allowlist: %v", err)
	}

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

	if err := SetAllowlist("fc", []CallerConfig{
		{ID: "abc", Rules: []CallRule{{Path: "/abc", Methods: map[string]RequestConstraint{"GET": {}}}}},
		{Rules: []CallRule{{Path: "/wild", Methods: map[string]RequestConstraint{"GET": {}}}}},
	}); err != nil {
		t.Fatalf("failed to set allowlist: %v", err)
	}

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

func TestSetAllowlistDuplicateCaller(t *testing.T) {
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	err := SetAllowlist("dup", []CallerConfig{{ID: "a"}, {ID: "a"}})
	if err == nil {
		t.Fatal("expected error for duplicate caller id")
	}
}

func TestSetAllowlistDuplicateRule(t *testing.T) {
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	callers := []CallerConfig{{
		ID: "a",
		Rules: []CallRule{
			{Path: "/x", Methods: map[string]RequestConstraint{"GET": {}}},
			{Path: "/x", Methods: map[string]RequestConstraint{"GET": {}}},
		},
	}}
	err := SetAllowlist("dup", callers)
	if err == nil {
		t.Fatal("expected error for duplicate rule")
	}
}

func TestSetAllowlistLowercaseMethod(t *testing.T) {
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	if err := SetAllowlist("case", []CallerConfig{{ID: "*", Rules: []CallRule{{Path: "/ok", Methods: map[string]RequestConstraint{"get": {}}}}}}); err != nil {
		t.Fatalf("failed to set allowlist: %v", err)
	}

	integ := &Integration{Name: "case"}
	if _, ok := findConstraint(integ, "*", "/ok", http.MethodGet); !ok {
		t.Fatal("expected match for uppercase method")
	}
}
