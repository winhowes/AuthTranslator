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
	if !validateRequest(r, RequestConstraint{Headers: map[string][]string{"X-Test": {"val"}}}) {
		t.Fatal("expected header match")
	}
	r2 := httptest.NewRequest(http.MethodGet, "http://x", nil)
	if validateRequest(r2, RequestConstraint{Headers: map[string][]string{"X-Test": {"val"}}}) {
		t.Fatal("expected failure without header")
	}

	r3 := httptest.NewRequest(http.MethodGet, "http://x", nil)
	r3.Header.Set("X-Test", "v")
	if !validateRequest(r3, RequestConstraint{Headers: map[string][]string{"x-test": {"v"}}}) {
		t.Fatal("expected case-insensitive header match")
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

func TestValidateRequestQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://x?a=1&a=2&b=3", nil)
	cons := RequestConstraint{Query: map[string][]string{"a": {"1"}, "b": {"3"}}}
	if !validateRequest(r, cons) {
		t.Fatal("expected query match")
	}
	r2 := httptest.NewRequest(http.MethodGet, "http://x?a=1", nil)
	if validateRequest(r2, cons) {
		t.Fatal("expected missing query to fail")
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

func TestSplitPathEmpty(t *testing.T) {
	got := splitPath("")
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %v", got)
	}
}
