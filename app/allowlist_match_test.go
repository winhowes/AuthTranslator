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

func TestValidateRequestUnknownContentType(t *testing.T) {
	r := newRequest(http.MethodPost, "http://x", "text/plain", []byte("ignored"))
	cons := RequestConstraint{Body: map[string]interface{}{"foo": "bar"}}
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
	if validateRequest(r, RequestConstraint{Body: map[string]interface{}{"a": "b"}}) {
		t.Fatal("expected false on body read error")
	}

	// bad JSON
	r2 := httptest.NewRequest(http.MethodPost, "http://x", strings.NewReader("{"))
	r2.Header.Set("Content-Type", "application/json")
	if validateRequest(r2, RequestConstraint{Body: map[string]interface{}{"a": "b"}}) {
		t.Fatal("expected false on json parse error")
	}

	// bad form encoding
	r3 := httptest.NewRequest(http.MethodPost, "http://x", strings.NewReader("%zz"))
	r3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if validateRequest(r3, RequestConstraint{Body: map[string]interface{}{"a": "1"}}) {
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

func TestToFloatVariousTypes(t *testing.T) {
	cases := []struct {
		val  interface{}
		want float64
		ok   bool
	}{
		{int(1), 1, true},
		{int8(2), 2, true},
		{int16(3), 3, true},
		{int32(4), 4, true},
		{int64(5), 5, true},
		{uint(6), 6, true},
		{uint8(7), 7, true},
		{uint16(8), 8, true},
		{uint32(9), 9, true},
		{uint64(10), 10, true},
		{float32(11.5), 11.5, true},
		{float64(12.5), 12.5, true},
		{"nope", 0, false},
	}
	for i, tt := range cases {
		got, ok := toFloat(tt.val)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("case %d: toFloat(%T)=(%v,%v) want (%v,%v)", i, tt.val, got, ok, tt.want, tt.ok)
		}
	}
}

func TestMatchBodyMapReasonSuccess(t *testing.T) {
	data := map[string]interface{}{
		"a":   "b",
		"arr": []interface{}{float64(1), float64(2)},
	}
	rule := map[string]interface{}{
		"a":   "b",
		"arr": []interface{}{float64(1)},
	}
	ok, reason := matchBodyMapReason(data, rule)
	if !ok || reason != "" {
		t.Fatalf("expected success, got ok=%v reason=%q", ok, reason)
	}
}

func TestMatchBodyMapReasonMissingField(t *testing.T) {
	data := map[string]interface{}{"a": "b"}
	rule := map[string]interface{}{"a": "b", "c": "d"}
	ok, reason := matchBodyMapReason(data, rule)
	if ok || reason != "missing body field c" {
		t.Fatalf("expected missing field failure, got ok=%v reason=%q", ok, reason)
	}
}

func TestMatchBodyMapReasonNestedMismatch(t *testing.T) {
	data := map[string]interface{}{"a": map[string]interface{}{"b": "c"}}
	rule := map[string]interface{}{"a": map[string]interface{}{"b": "d"}}
	ok, reason := matchBodyMapReason(data, rule)
	if ok || reason != "body field a.b value mismatch" {
		t.Fatalf("expected mismatch failure, got ok=%v reason=%q", ok, reason)
	}
}

func TestMatchBodyMapSuccess(t *testing.T) {
	data := map[string]interface{}{
		"a":   "b",
		"arr": []interface{}{float64(1), float64(2)},
	}
	rule := map[string]interface{}{
		"a":   "b",
		"arr": []interface{}{float64(1)},
	}
	if !matchBodyMap(data, rule) {
		t.Fatal("expected matchBodyMap to succeed")
	}
}

func TestMatchBodyMapFailure(t *testing.T) {
	data := map[string]interface{}{"a": "b"}
	rule := map[string]interface{}{"a": "b", "c": "d"}
	if matchBodyMap(data, rule) {
		t.Fatal("expected matchBodyMap to fail")
	}
}
