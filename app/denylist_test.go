package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
)

func resetDenylists() {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()
}

func TestSetDenylistDuplicateRule(t *testing.T) {
	resetDenylists()

	callers := []DenylistCaller{{
		ID: "caller",
		Rules: []CallRule{
			{Path: "/dup", Methods: map[string]RequestConstraint{"GET": {}}},
			{Path: "/dup", Methods: map[string]RequestConstraint{"get": {}}},
		},
	}}
	if err := SetDenylist("dup", callers); err == nil {
		t.Fatal("expected duplicate rule error")
	}
}

func TestSetDenylistDuplicateCaller(t *testing.T) {
	resetDenylists()

	callers := []DenylistCaller{
		{
			ID: "",
			Rules: []CallRule{{
				Path:    "/first",
				Methods: map[string]RequestConstraint{"GET": {}},
			}},
		},
		{
			ID: "*",
			Rules: []CallRule{{
				Path:    "/second",
				Methods: map[string]RequestConstraint{"POST": {}},
			}},
		},
	}

	if err := SetDenylist("dup", callers); err == nil {
		t.Fatal("expected duplicate caller error")
	}
}

func TestSetDenylistRejectsInvalidRules(t *testing.T) {
	tests := []struct {
		name    string
		callers []DenylistCaller
		wantErr string
	}{
		{
			name: "MissingPath",
			callers: []DenylistCaller{{
				ID: "", // normalized to *
				Rules: []CallRule{{
					Path:    "",
					Methods: map[string]RequestConstraint{"GET": {}},
				}},
			}},
			wantErr: "missing path",
		},
		{
			name: "MissingMethods",
			callers: []DenylistCaller{{
				ID: "caller",
				Rules: []CallRule{{
					Path:    "/no-methods",
					Methods: nil,
				}},
			}},
			wantErr: "has no methods",
		},
		{
			name: "BlankMethod",
			callers: []DenylistCaller{{
				ID: "caller",
				Rules: []CallRule{{
					Path:    "/blank",
					Methods: map[string]RequestConstraint{"   ": {}},
				}},
			}},
			wantErr: "invalid method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetDenylists()

			err := SetDenylist("invalid", tt.callers)
			if err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error to contain %q, got %v", tt.wantErr, err)
			}

			denylists.RLock()
			_, ok := denylists.m["invalid"]
			denylists.RUnlock()
			if ok {
				t.Fatal("denylist should not be stored on validation error")
			}
		})
	}
}

func TestSetDenylistNormalizesEntries(t *testing.T) {
	resetDenylists()

	callers := []DenylistCaller{{
		ID: "",
		Rules: []CallRule{{
			Path: "/blocked",
			Methods: map[string]RequestConstraint{
				" get ": {Headers: map[string][]string{"X-Foo": {"bar"}}},
			},
		}},
	}}

	if err := SetDenylist("normalize", callers); err != nil {
		t.Fatalf("failed to set denylist: %v", err)
	}

	denylists.RLock()
	defer denylists.RUnlock()

	rules, ok := denylists.m["normalize"]["*"]
	if !ok {
		t.Fatal("expected caller ID to be normalized to *")
	}
	if len(rules) != 1 {
		t.Fatalf("expected one rule, got %d", len(rules))
	}
	if _, ok := rules[0].Methods["GET"]; !ok {
		t.Fatalf("expected method key to be uppercased, got keys %v", reflect.ValueOf(rules[0].Methods).MapKeys())
	}
	if !reflect.DeepEqual(rules[0].Segments, []string{"blocked"}) {
		t.Fatalf("unexpected segments: %+v", rules[0].Segments)
	}
}

func TestMatchDenylist(t *testing.T) {
	resetDenylists()

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
	req.Header.Set("X-Block", "yes")
	integ := &Integration{Name: "deny"}
	blocked, reason := matchDenylist(integ, "caller", req)
	if !blocked {
		t.Fatal("expected denylist to match")
	}
	if !strings.Contains(reason, "/blocked") {
		t.Fatalf("unexpected reason: %s", reason)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://deny/blocked", nil)
	blocked, _ = matchDenylist(integ, "caller", req2)
	if blocked {
		t.Fatal("unexpected denylist match without header")
	}
}

func TestMatchDenylistWildcardCaller(t *testing.T) {
	resetDenylists()

	if err := SetDenylist("deny", []DenylistCaller{{
		ID: "",
		Rules: []CallRule{{
			Path: "/wild",
			Methods: map[string]RequestConstraint{
				"GET": {Query: map[string][]string{"deny": {"1", "2"}}},
			},
		}},
	}}); err != nil {
		t.Fatalf("failed to set denylist: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://deny/wild?deny=1&deny=2&extra=3", nil)
	integ := &Integration{Name: "deny"}
	blocked, reason := matchDenylist(integ, "unknown", req)
	if !blocked {
		t.Fatal("expected wildcard denylist to match")
	}
	if !strings.Contains(reason, "/wild") {
		t.Fatalf("unexpected reason: %s", reason)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://deny/wild?deny=1", nil)
	blocked, _ = matchDenylist(integ, "unknown", req2)
	if blocked {
		t.Fatal("unexpected match when query values missing")
	}
}

func TestMatchDenylistCallerPrecedence(t *testing.T) {
	resetDenylists()

	if err := SetDenylist("deny", []DenylistCaller{
		{
			ID: "caller",
			Rules: []CallRule{{
				Path: "/only",
				Methods: map[string]RequestConstraint{
					"GET": {Headers: map[string][]string{"X-Mode": {"strict"}}},
				},
			}},
		},
		{
			ID: "*",
			Rules: []CallRule{{
				Path: "/fallback",
				Methods: map[string]RequestConstraint{
					"POST": {},
				},
			}},
		},
	}); err != nil {
		t.Fatalf("failed to set denylist: %v", err)
	}

	integ := &Integration{Name: "deny"}

	req := httptest.NewRequest(http.MethodGet, "http://deny/only", nil)
	req.Header.Set("X-Mode", "strict")
	blocked, reason := matchDenylist(integ, "caller", req)
	if !blocked {
		t.Fatal("expected denylist to match specific caller rule")
	}
	if strings.Contains(reason, "caller *") {
		t.Fatalf("expected specific caller reason, got %q", reason)
	}

	req2 := httptest.NewRequest(http.MethodPost, "http://deny/fallback", nil)
	blocked, reason = matchDenylist(integ, "caller", req2)
	if !blocked {
		t.Fatal("expected denylist to fall back to wildcard caller")
	}
	if !strings.Contains(reason, "caller * POST /fallback") {
		t.Fatalf("unexpected reason for wildcard match: %q", reason)
	}
}

func TestMatchDenylistEmptyCallerUsesWildcard(t *testing.T) {
	resetDenylists()

	if err := SetDenylist("deny", []DenylistCaller{{
		ID: "",
		Rules: []CallRule{{
			Path: "/path",
			Methods: map[string]RequestConstraint{
				"GET": {},
			},
		}},
	}}); err != nil {
		t.Fatalf("failed to set denylist: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://deny/path", nil)
	blocked, reason := matchDenylist(&Integration{Name: "deny"}, "", req)
	if !blocked {
		t.Fatal("expected denylist to match empty caller using wildcard")
	}
	if !strings.Contains(reason, "caller * GET /path") {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

func TestMatchDenylistTrimsMethod(t *testing.T) {
	resetDenylists()

	if err := SetDenylist("deny", []DenylistCaller{{
		ID: "caller",
		Rules: []CallRule{{
			Path: "/blocked",
			Methods: map[string]RequestConstraint{
				" get ": {},
			},
		}},
	}}); err != nil {
		t.Fatalf("failed to set denylist: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://deny/blocked", nil)
	integ := &Integration{Name: "deny"}
	blocked, _ := matchDenylist(integ, "caller", req)
	if !blocked {
		t.Fatal("expected denylist to match with trimmed method")
	}
}

func TestMatchDenylistIntegrationCaseInsensitive(t *testing.T) {
	resetDenylists()

	if err := SetDenylist("CaSe", []DenylistCaller{{
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

	req := httptest.NewRequest(http.MethodGet, "http://case/blocked", nil)
	req.Header.Set("X-Block", "yes")
	integ := &Integration{Name: "CaSe"}
	blocked, _ := matchDenylist(integ, "caller", req)
	if !blocked {
		t.Fatal("expected denylist to match regardless of integration name case")
	}
}

func TestConstraintMatchesRequestJSON(t *testing.T) {
	body := `{"foo":{"bar":"baz","extra":1},"tags":["a","b"]}`
	req := httptest.NewRequest(http.MethodPost, "http://json/path", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	cons := RequestConstraint{Body: map[string]interface{}{
		"foo":  map[string]interface{}{"bar": "baz"},
		"tags": []interface{}{"a"},
	}}
	if !constraintMatchesRequest(req, cons) {
		t.Fatal("expected JSON body to match constraint")
	}
}

func TestConstraintMatchesRequestJSONContentTypeCaseInsensitive(t *testing.T) {
	body := `{"foo":"bar"}`
	req := httptest.NewRequest(http.MethodPost, "http://json/path", strings.NewReader(body))
	req.Header.Set("Content-Type", "Application/JSON; charset=utf-8")
	cons := RequestConstraint{Body: map[string]interface{}{
		"foo": "bar",
	}}
	if !constraintMatchesRequest(req, cons) {
		t.Fatal("expected JSON body to match constraint regardless of content type case")
	}
}

func TestConstraintMatchesRequestForm(t *testing.T) {
	vals := url.Values{"a": {"1", "2"}, "b": {"x"}}
	req := httptest.NewRequest(http.MethodPost, "http://form/path", strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cons := RequestConstraint{Body: map[string]interface{}{
		"a": []interface{}{"1"},
		"b": "x",
	}}
	if !constraintMatchesRequest(req, cons) {
		t.Fatal("expected form body to match constraint")
	}
}

func TestConstraintMatchesRequestFormContentTypeCaseInsensitive(t *testing.T) {
	vals := url.Values{"foo": {"bar"}}
	req := httptest.NewRequest(http.MethodPost, "http://form/path", strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "Application/X-Www-Form-Urlencoded")
	cons := RequestConstraint{Body: map[string]interface{}{
		"foo": "bar",
	}}
	if !constraintMatchesRequest(req, cons) {
		t.Fatal("expected form body to match constraint regardless of content type case")
	}
}

func TestConstraintMatchesRequestUnsupportedBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://plain/path", strings.NewReader("test"))
	req.Header.Set("Content-Type", "text/plain")
	cons := RequestConstraint{Body: map[string]interface{}{"plain": "text"}}
	if constraintMatchesRequest(req, cons) {
		t.Fatal("expected unsupported content type not to match")
	}
}

func TestConstraintMatchesRequestBodyReadError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://limit/path", strings.NewReader("{\"foo\":\"bar\"}"))
	req.Header.Set("Content-Type", "application/json")
	cons := RequestConstraint{Body: map[string]interface{}{"foo": "bar"}}

	oldMax := authplugins.MaxBodySize
	authplugins.MaxBodySize = 1
	defer func() { authplugins.MaxBodySize = oldMax }()

	if constraintMatchesRequest(req, cons) {
		t.Fatal("expected body read error to prevent match")
	}
}

func TestConstraintMatchesRequestHeaderCaseInsensitive(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://headers/path", nil)
	req.Header.Set("X-Token", "abc123")
	cons := RequestConstraint{Headers: map[string][]string{"x-token": {"abc123"}}}
	if !constraintMatchesRequest(req, cons) {
		t.Fatal("expected header constraint to be case insensitive")
	}
}
