package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
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

func TestSetDenylistNormalizesInput(t *testing.T) {
	resetDenylists()

	callers := []DenylistCaller{{
		Rules: []CallRule{{
			Path:    "/foo/**",
			Methods: map[string]RequestConstraint{"post": {}},
		}},
	}}

	if err := SetDenylist("TeSt", callers); err != nil {
		t.Fatalf("failed to set denylist: %v", err)
	}

	denylists.RLock()
	integration, ok := denylists.m["test"]
	denylists.RUnlock()
	if !ok {
		t.Fatal("expected normalized integration name")
	}

	rules, ok := integration["*"]
	if !ok {
		t.Fatal("expected caller ID to default to *")
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	rule := rules[0]
	if len(rule.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(rule.Methods))
	}
	if _, ok := rule.Methods["POST"]; !ok {
		t.Fatal("expected method to be uppercased")
	}
	if !reflect.DeepEqual(rule.Segments, []string{"foo", "**"}) {
		t.Fatalf("unexpected segments: %+v", rule.Segments)
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

	callers := []DenylistCaller{
		{
			ID: "caller",
			Rules: []CallRule{{
				Path: "/blocked/*",
				Methods: map[string]RequestConstraint{
					"GET": {Query: map[string][]string{"foo": {"nope"}}},
				},
			}},
		},
		{
			ID: "*",
			Rules: []CallRule{{
				Path: "/blocked/*",
				Methods: map[string]RequestConstraint{
					"GET": {Query: map[string][]string{"foo": {"bar"}}},
				},
			}},
		},
	}

	if err := SetDenylist("deny", callers); err != nil {
		t.Fatalf("failed to set denylist: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://deny/blocked/item?foo=bar", nil)
	integ := &Integration{Name: "deny"}
	blocked, reason := matchDenylist(integ, "caller", req)
	if !blocked {
		t.Fatal("expected wildcard denylist to match")
	}
	if !strings.Contains(reason, "caller *") {
		t.Fatalf("expected wildcard reason, got %q", reason)
	}
	if !strings.Contains(reason, "/blocked/*") {
		t.Fatalf("unexpected reason: %s", reason)
	}

	reqNoQuery := httptest.NewRequest(http.MethodGet, "http://deny/blocked/item", nil)
	blocked, _ = matchDenylist(integ, "caller", reqNoQuery)
	if blocked {
		t.Fatal("expected denylist not to match without query parameter")
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

func TestConstraintMatchesRequestHeaderCanonicalization(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example/path", nil)
	req.Header.Set("X-Block", "yes")
	cons := RequestConstraint{Headers: map[string][]string{"x-block": {"yes"}}}
	if !constraintMatchesRequest(req, cons) {
		t.Fatal("expected header constraint to be case-insensitive")
	}
}

func TestConstraintMatchesRequestQueryMismatch(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example/path?foo=bar", nil)
	cons := RequestConstraint{Query: map[string][]string{"foo": {"baz"}}}
	if constraintMatchesRequest(req, cons) {
		t.Fatal("expected query mismatch not to match")
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
