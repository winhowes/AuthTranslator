package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"

	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/basic"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/google_oidc"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/token"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestAllowlist(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

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
	if rr2.Header().Get("X-AT-Error-Reason") == "" {
		t.Fatal("missing X-AT-Error-Reason header")
	}
}

func TestFindConstraintExpandsCallerAndWildcardCapabilities(t *testing.T) {
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	orig := integrationplugins.AllCapabilities()
	snapshot := map[string]map[string]integrationplugins.CapabilitySpec{}
	for integ, caps := range orig {
		snapshot[integ] = map[string]integrationplugins.CapabilitySpec{}
		for name, spec := range caps {
			snapshot[integ][name] = spec
		}
	}
	t.Cleanup(func() {
		reg := integrationplugins.AllCapabilities()
		for k := range reg {
			delete(reg, k)
		}
		for integ, caps := range snapshot {
			reg[integ] = caps
		}
	})

	integrationplugins.RegisterCapability("capboth", "cap", integrationplugins.CapabilitySpec{
		Generate: func(map[string]interface{}) ([]integrationplugins.CallRule, error) {
			return []integrationplugins.CallRule{{
				Path:    "/capability",
				Methods: map[string]integrationplugins.RequestConstraint{http.MethodGet: {}},
			}}, nil
		},
	})

	if err := SetAllowlist("capboth", []CallerConfig{
		{ID: "direct", Capabilities: []integrationplugins.CapabilityConfig{{Name: "cap"}}},
		{ID: "*", Capabilities: []integrationplugins.CapabilityConfig{{Name: "cap"}}},
	}); err != nil {
		t.Fatalf("failed to set allowlist: %v", err)
	}

	integ := &Integration{Name: "capboth"}
	if _, ok := findConstraint(integ, "direct", "/capability", http.MethodGet); !ok {
		t.Fatal("expected capability expansion for specific caller")
	}
	if _, ok := findConstraint(integ, "other", "/capability", http.MethodGet); !ok {
		t.Fatal("expected capability expansion for wildcard caller")
	}
}

func TestFindConstraintExpandsCapabilitiesOnLookup(t *testing.T) {
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	orig := integrationplugins.AllCapabilities()
	snapshot := map[string]map[string]integrationplugins.CapabilitySpec{}
	for integ, caps := range orig {
		snapshot[integ] = map[string]integrationplugins.CapabilitySpec{}
		for name, spec := range caps {
			snapshot[integ][name] = spec
		}
	}
	t.Cleanup(func() {
		reg := integrationplugins.AllCapabilities()
		for k := range reg {
			delete(reg, k)
		}
		for integ, caps := range snapshot {
			reg[integ] = caps
		}
	})

	integrationplugins.RegisterCapability("lookup", "cap", integrationplugins.CapabilitySpec{
		Generate: func(map[string]interface{}) ([]integrationplugins.CallRule, error) {
			return []integrationplugins.CallRule{{
				Path:     "/capability",
				Methods:  map[string]integrationplugins.RequestConstraint{http.MethodGet: {}},
				Segments: splitPath("/capability"),
			}}, nil
		},
	})

	allowlists.Lock()
	allowlists.m["lookup"] = map[string]CallerConfig{
		"direct": {
			ID:           "direct",
			Capabilities: []integrationplugins.CapabilityConfig{{Name: "cap"}},
		},
		"*": {
			Capabilities: []integrationplugins.CapabilityConfig{{Name: "cap"}},
		},
	}
	allowlists.Unlock()

	integ := &Integration{Name: "lookup"}
	if _, ok := findConstraint(integ, "direct", "/capability", http.MethodGet); !ok {
		t.Fatal("expected capability expansion for caller during lookup")
	}
	if _, ok := findConstraint(integ, "other", "/capability", http.MethodGet); !ok {
		t.Fatal("expected capability expansion for wildcard during lookup")
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

func TestSetAllowlistMethodNormalization(t *testing.T) {
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	if err := SetAllowlist("case", []CallerConfig{{ID: "*", Rules: []CallRule{{Path: "/ok", Methods: map[string]RequestConstraint{" get ": {}}}}}}); err != nil {
		t.Fatalf("failed to set allowlist: %v", err)
	}

	integ := &Integration{Name: "case"}
	if _, ok := findConstraint(integ, "*", "/ok", http.MethodGet); !ok {
		t.Fatal("expected match for uppercase method")
	}
}

func TestMatchSegmentsDoubleStarFailure(t *testing.T) {
	if matchSegments([]string{"**", "a"}, []string{"b"}) {
		t.Fatal("expected pattern to fail to match path")
	}
}

func TestValidateRequestReasonQueryValueMismatch(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/?q=two", nil)
	constraint := RequestConstraint{Query: map[string][]string{"q": {"one"}}}
	if ok, reason := validateRequestReason(req, constraint); ok || reason == "" {
		t.Fatalf("expected query validation failure, got ok=%v reason=%q", ok, reason)
	}
}

func TestValidateRequestReasonFormMismatch(t *testing.T) {
	body := strings.NewReader("other=x")
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	constraint := RequestConstraint{Body: map[string]interface{}{"field": "value"}}
	if ok, reason := validateRequestReason(req, constraint); ok || reason == "" {
		t.Fatalf("expected form validation failure, got ok=%v reason=%q", ok, reason)
	}
}

func TestConstraintFailureHeader(t *testing.T) {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	t.Setenv("TOK", "secret")
	integ := Integration{
		Name:         "consfail",
		Destination:  backend.URL,
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "X-Auth"}}},
	}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("failed to add integration: %v", err)
	}
	if err := SetAllowlist("consfail", []CallerConfig{
		{ID: "*", Rules: []CallRule{{Path: "/path", Methods: map[string]RequestConstraint{"GET": {Headers: map[string][]string{"X-Need": {"val"}}}}}}},
	}); err != nil {
		t.Fatalf("failed to set allowlist: %v", err)
	}
	t.Cleanup(func() {
		integ.inLimiter.Stop()
		integ.outLimiter.Stop()
	})

	req := httptest.NewRequest(http.MethodGet, "http://consfail/path", nil)
	req.Host = "consfail"
	req.Header.Set("X-Auth", "secret")
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	if val := rr.Header().Get("X-AT-Error-Reason"); val == "" {
		t.Fatal("missing X-AT-Error-Reason header")
	} else if !strings.Contains(val, "missing header X-Need") {
		t.Fatalf("unexpected error header: %s", val)
	}
}

func TestFindConstraintCapability(t *testing.T) {
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	// save and restore capability registry
	orig := make(map[string]map[string]integrationplugins.CapabilitySpec)
	for integ, caps := range integrationplugins.AllCapabilities() {
		m := make(map[string]integrationplugins.CapabilitySpec, len(caps))
		for name, spec := range caps {
			m[name] = spec
		}
		orig[integ] = m
	}
	reg := integrationplugins.AllCapabilities()
	for k := range reg {
		delete(reg, k)
	}
	t.Cleanup(func() {
		reg := integrationplugins.AllCapabilities()
		for k := range reg {
			delete(reg, k)
		}
		for integ, caps := range orig {
			reg[integ] = caps
		}
	})

	integrationplugins.RegisterCapability("capfi", "cap", integrationplugins.CapabilitySpec{
		Generate: func(map[string]interface{}) ([]integrationplugins.CallRule, error) {
			return []integrationplugins.CallRule{{Path: "/c", Methods: map[string]integrationplugins.RequestConstraint{"GET": {}}}}, nil
		},
	})

	if err := SetAllowlist("capfi", []CallerConfig{{
		ID:           "id",
		Capabilities: []integrationplugins.CapabilityConfig{{Name: "cap"}},
	}}); err != nil {
		t.Fatalf("failed to set allowlist: %v", err)
	}

	integ := &Integration{Name: "capfi"}
	if _, ok := findConstraint(integ, "id", "/c", http.MethodGet); !ok {
		t.Fatal("expected capability constraint match")
	}
}

func TestValidateRequestReasonJSONContentTypeCaseInsensitive(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://case/json", strings.NewReader(`{"foo":"bar"}`))
	req.Header.Set("Content-Type", "Application/JSON; charset=utf-8")
	cons := RequestConstraint{Body: map[string]interface{}{"foo": "bar"}}
	if ok, reason := validateRequestReason(req, cons); !ok {
		t.Fatalf("expected JSON constraint to pass regardless of content type case: %s", reason)
	}
}

func TestValidateRequestReasonFormContentTypeCaseInsensitive(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://case/form", strings.NewReader("foo=bar"))
	req.Header.Set("Content-Type", "Application/X-Www-Form-Urlencoded")
	cons := RequestConstraint{Body: map[string]interface{}{"foo": "bar"}}
	if ok, reason := validateRequestReason(req, cons); !ok {
		t.Fatalf("expected form constraint to pass regardless of content type case: %s", reason)
	}
}

func TestMatchValueNotOkBranches(t *testing.T) {
	if matchValue("not-a-map", map[string]interface{}{"a": 1}) {
		t.Fatal("expected map type mismatch to fail")
	}
	if matchValue(map[string]interface{}{"a": 1}, map[string]interface{}{"a": 1, "b": 2}) {
		t.Fatal("expected missing map key to fail")
	}
	if matchValue("not-an-array", []interface{}{"a"}) {
		t.Fatal("expected array type mismatch to fail")
	}
}

func TestMatchValueReasonNotOkBranches(t *testing.T) {
	if ok, reason := matchValueReason("not-a-map", map[string]interface{}{"a": 1}, ""); ok {
		t.Fatalf("expected map type mismatch to fail, got reason: %s", reason)
	}
	if ok, reason := matchValueReason(map[string]interface{}{"a": 1}, map[string]interface{}{"a": 1, "b": 2}, ""); ok {
		t.Fatalf("expected missing field to fail, got reason: %s", reason)
	}
	if ok, reason := matchValueReason("not-an-array", []interface{}{"a"}, "items"); ok {
		t.Fatalf("expected array type mismatch to fail, got reason: %s", reason)
	}
	if ok, reason := matchValueReason([]interface{}{"x"}, []interface{}{"y"}, "items"); ok {
		t.Fatalf("expected missing array element to fail, got reason: %s", reason)
	}
	if ok, reason := matchValueReason(map[string]interface{}{"a": "b"}, map[string]interface{}{"a": "c"}, ""); ok {
		t.Fatalf("expected value mismatch to fail, got reason: %s", reason)
	}
}

func TestMatchFormReasonAndValidateRequestFailures(t *testing.T) {
	vals := url.Values{"foo": {"bar"}}
	if ok, reason := matchFormReason(vals, map[string]interface{}{"foo": "baz"}); ok {
		t.Fatalf("expected form value mismatch to fail, got reason: %s", reason)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example.com", strings.NewReader("foo=bar"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Test", "wrong")
	cons := RequestConstraint{
		Headers: map[string][]string{"X-Test": {"expected"}},
		Body:    map[string]interface{}{"foo": "baz"},
	}
	if ok, reason := validateRequestReason(req, cons); ok {
		t.Fatalf("expected validateRequestReason to fail, got success with reason: %s", reason)
	}
}
