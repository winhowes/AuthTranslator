package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/token"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestAllowlistCaseInsensitive(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	t.Setenv("TOK", "secret")
	integ := Integration{
		Name:         "foo",
		Destination:  backend.URL,
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "X-Auth"}}},
	}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	// allow only /ok path; integration name uses different case
	if err := SetAllowlist("FOO", []CallerConfig{{ID: "*", Rules: []CallRule{{Path: "/ok", Methods: map[string]RequestConstraint{"GET": {}}}}}}); err != nil {
		t.Fatalf("failed to set allowlist: %v", err)
	}
	t.Cleanup(func() {
		integ.inLimiter.Stop()
		integ.outLimiter.Stop()
	})

	req := httptest.NewRequest(http.MethodGet, "http://foo/deny", nil)
	req.Host = "foo"
	req.Header.Set("X-Auth", "secret")
	rr := httptest.NewRecorder()
	proxyHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}
