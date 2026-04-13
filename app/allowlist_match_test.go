package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	cons := RequestConstraint{Body: map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"a": map[string]interface{}{
				"type":  "string",
				"const": "b",
			},
			"arr": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "integer",
				},
			},
		},
		"required": []interface{}{"a"},
	}}
	if !validateRequest(r, cons) {
		t.Fatal("expected body match")
	}
}

func TestValidateRequestFormBody(t *testing.T) {
	form := url.Values{"a": {"1", "3"}, "b": {"2"}}
	r := newRequest(http.MethodPost, "http://x", "application/x-www-form-urlencoded", []byte(form.Encode()))
	cons := RequestConstraint{Body: map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"a": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "string",
				},
				"minItems": 2,
			},
			"b": map[string]interface{}{
				"type":  "string",
				"const": "2",
			},
		},
		"required": []interface{}{"a", "b"},
	}}
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
	cons := RequestConstraint{Body: map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"a": map[string]interface{}{
				"type":  "string",
				"const": "b",
			},
		},
		"required": []interface{}{"a"},
	}}
	if validateRequest(r, cons) {
		t.Fatal("expected body mismatch to fail")
	}
}

func TestValidateRequestUnknownContentType(t *testing.T) {
	r := newRequest(http.MethodPost, "http://x", "text/plain", []byte("ignored"))
	cons := RequestConstraint{Body: map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"foo": map[string]interface{}{
				"type":  "string",
				"const": "bar",
			},
		},
		"required": []interface{}{"foo"},
	}}
	if !validateRequest(r, cons) {
		t.Fatal("expected body check skipped on unknown content type")
	}
}

func TestSplitPathEmpty(t *testing.T) {
	got := splitPath("")
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %v", got)
	}
}

// errReadCloser returns an error when read to trigger GetBody failures.
type errReadCloser struct{}

func (errReadCloser) Read(p []byte) (int, error) { return 0, errors.New("boom") }
func (errReadCloser) Close() error               { return nil }

func TestValidateRequestBodyErrors(t *testing.T) {
	// read error
	r := httptest.NewRequest(http.MethodPost, "http://x", nil)
	r.Body = errReadCloser{}
	r.Header.Set("Content-Type", "application/json")
	if validateRequest(r, RequestConstraint{Body: map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"a": map[string]interface{}{
				"type":  "string",
				"const": "b",
			},
		},
		"required": []interface{}{"a"},
	}}) {
		t.Fatal("expected false on body read error")
	}

	// bad JSON
	r2 := httptest.NewRequest(http.MethodPost, "http://x", strings.NewReader("{"))
	r2.Header.Set("Content-Type", "application/json")
	if validateRequest(r2, RequestConstraint{Body: map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"a": map[string]interface{}{
				"type":  "string",
				"const": "b",
			},
		},
		"required": []interface{}{"a"},
	}}) {
		t.Fatal("expected false on json parse error")
	}

	// bad form encoding
	r3 := httptest.NewRequest(http.MethodPost, "http://x", strings.NewReader("%zz"))
	r3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if validateRequest(r3, RequestConstraint{Body: map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"a": map[string]interface{}{
				"type":  "string",
				"const": "1",
			},
		},
		"required": []interface{}{"a"},
	}}) {
		t.Fatal("expected false on form parse error")
	}

	// no constraints should succeed
	r4 := httptest.NewRequest(http.MethodGet, "http://x", nil)
	if !validateRequest(r4, RequestConstraint{}) {
		t.Fatal("expected success with no constraints")
	}
}

func TestMatchSegmentsEdgeCases(t *testing.T) {
	cases := []struct {
		pattern []string
		path    []string
		ok      bool
	}{
		{[]string{}, []string{}, true},
		{[]string{"a"}, []string{}, false},
		{[]string{"**"}, []string{}, true},
		{[]string{"**"}, []string{"a"}, true},
		{[]string{"**", "b"}, []string{"a", "b"}, true},
		{[]string{"*", "b"}, []string{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"a"}, false},
	}
	for i, tt := range cases {
		if got := matchSegments(tt.pattern, tt.path); got != tt.ok {
			t.Errorf("case %d: got %v want %v", i, got, tt.ok)
		}
	}
}
