package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestConstraintMatchesRequestUnsupportedBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://plain/path", strings.NewReader("test"))
	req.Header.Set("Content-Type", "text/plain")
	cons := RequestConstraint{Body: map[string]interface{}{"plain": "text"}}
	if constraintMatchesRequest(req, cons) {
		t.Fatal("expected unsupported content type not to match")
	}
}
