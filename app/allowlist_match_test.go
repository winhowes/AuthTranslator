package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestMatchPath verifies wildcard path matching
func TestMatchPath(t *testing.T) {
	cases := []struct {
		patt string
		path string
		ok   bool
	}{
		{"/foo/*", "/foo/bar", true},
		{"/foo/*", "/foo/bar/baz", false},
		{"/foo/**", "/foo/bar/baz", true},
		{"/bar/**", "/bar", true},
		{"**", "/any/thing", true},
		{"**/bar", "foo/bar", true},
		{"**/bar", "bar", true},
		{"foo/**/baz", "foo/bar/baz", true},
		{"foo/**/baz", "foo/baz", true},
		{"foo/**/baz", "foo/a/b/c/baz", true},
	}
	for _, c := range cases {
		if got := matchPath(c.patt, c.path); got != c.ok {
			t.Errorf("matchPath(%q,%q)=%v want %v", c.patt, c.path, got, c.ok)
		}
	}
}

// helper to build request with body preserved
func newRequest(method, urlStr, ct string, body []byte) *http.Request {
	r := httptest.NewRequest(method, urlStr, bytes.NewReader(body))
	r.Header.Set("Content-Type", ct)
	return r
}

func TestValidateRequestHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://x", nil)
	r.Header.Set("X-Test", "val")
	if !validateRequest(r, RequestConstraint{Headers: []string{"X-Test"}}) {
		t.Fatal("expected header match")
	}
	r2 := httptest.NewRequest(http.MethodGet, "http://x", nil)
	if validateRequest(r2, RequestConstraint{Headers: []string{"X-Test"}}) {
		t.Fatal("expected failure without header")
	}
}

func TestValidateRequestJSONBody(t *testing.T) {
	body := []byte(`{"a":"b","arr":[1,2]}`)
	r := newRequest(http.MethodPost, "http://x", "application/json", body)
	cons := RequestConstraint{Body: map[string]interface{}{"a": "b", "arr": []interface{}{float64(1)}}}
	if !validateRequest(r, cons) {
		t.Fatal("expected body match")
	}
}

func TestValidateRequestFormBody(t *testing.T) {
	form := url.Values{"a": {"1", "3"}, "b": {"2"}}
	r := newRequest(http.MethodPost, "http://x", "application/x-www-form-urlencoded", []byte(form.Encode()))
	cons := RequestConstraint{Body: map[string]interface{}{"a": []interface{}{"1", "3"}, "b": "2"}}
	if !validateRequest(r, cons) {
		t.Fatal("expected form match")
	}
}

func TestValidateRequestBodyMismatch(t *testing.T) {
	body := []byte(`{"a":"x"}`)
	r := newRequest(http.MethodPost, "http://x", "application/json", body)
	cons := RequestConstraint{Body: map[string]interface{}{"a": "b"}}
	if validateRequest(r, cons) {
		t.Fatal("expected body mismatch to fail")
	}
}
