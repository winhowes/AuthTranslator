package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// buildReq builds a request and preserves the body for later reads.
func buildReq(method, urlStr, ct string, body []byte) *http.Request {
	r := httptest.NewRequest(method, urlStr, bytes.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	return r
}

func TestMatchPathTable(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		ok      bool
	}{
		{"*", "/foo", true},
		{"*", "/foo/bar", false},
		{"**", "/foo/bar", true},
		{"/foo/bar", "/foo/bar", true},
		{"/foo/bar", "/foo/bar/", true},
		{"/foo/*", "/foo/baz", true},
		{"/foo/*", "/foo/baz/qux", false},
		{"/foo/**", "/foo/baz/qux", true},
		{"/foo/*", "/foo", false},
	}

	for _, tt := range tests {
		if got := matchPath(tt.pattern, tt.path); got != tt.ok {
			t.Errorf("matchPath(%q,%q)=%v want %v", tt.pattern, tt.path, got, tt.ok)
		}
	}
}

func TestValidateRequestTable(t *testing.T) {
	form := url.Values{"a": {"1", "3"}, "b": {"2"}}
	bodyJSON := []byte(`{"a":"b","arr":[1,2]}`)

	tests := []struct {
		name   string
		r      *http.Request
		cons   RequestConstraint
		wantOK bool
	}{
		{
			name: "header present",
			r: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "http://x", nil)
				r.Header.Set("X-Test", "v")
				return r
			}(),
			cons:   RequestConstraint{Headers: map[string][]string{"X-Test": {"v"}}},
			wantOK: true,
		},
		{
			name:   "header missing",
			r:      httptest.NewRequest(http.MethodGet, "http://x", nil),
			cons:   RequestConstraint{Headers: map[string][]string{"X-Test": {"v"}}},
			wantOK: false,
		},
		{
			name:   "json body match",
			r:      buildReq(http.MethodPost, "http://x", "application/json", bodyJSON),
			cons:   RequestConstraint{Body: map[string]interface{}{"a": "b", "arr": []interface{}{float64(1)}}},
			wantOK: true,
		},
		{
			name:   "json body mismatch",
			r:      buildReq(http.MethodPost, "http://x", "application/json", []byte(`{"a":"x"}`)),
			cons:   RequestConstraint{Body: map[string]interface{}{"a": "b"}},
			wantOK: false,
		},
		{
			name:   "form match",
			r:      buildReq(http.MethodPost, "http://x", "application/x-www-form-urlencoded", []byte(form.Encode())),
			cons:   RequestConstraint{Body: map[string]interface{}{"a": []interface{}{"1", "3"}, "b": "2"}},
			wantOK: true,
		},
		{
			name:   "query match",
			r:      httptest.NewRequest(http.MethodGet, "http://x?a=1&b=2", nil),
			cons:   RequestConstraint{Query: map[string][]string{"a": {"1"}, "b": {"2"}}},
			wantOK: true,
		},
		{
			name:   "query missing",
			r:      httptest.NewRequest(http.MethodGet, "http://x?a=1", nil),
			cons:   RequestConstraint{Query: map[string][]string{"a": {"1"}, "b": {"2"}}},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		if got := validateRequest(tt.r, tt.cons); got != tt.wantOK {
			t.Errorf("%s: validateRequest=%v want %v", tt.name, got, tt.wantOK)
		}
	}
}

func TestValidateRequestReasonFailures(t *testing.T) {
	body := []byte(`{"a":"1"}`)
	tests := []struct {
		name string
		r    *http.Request
		cons RequestConstraint
		want string
	}{
		{
			name: "header missing",
			r:    httptest.NewRequest(http.MethodGet, "http://x", nil),
			cons: RequestConstraint{Headers: map[string][]string{"X-Test": {"v"}}},
			want: "missing header X-Test",
		},
		{
			name: "query missing",
			r:    httptest.NewRequest(http.MethodGet, "http://x?a=1", nil),
			cons: RequestConstraint{Query: map[string][]string{"a": {"1"}, "b": {"2"}}},
			want: "missing query param b",
		},
		{
			name: "body mismatch",
			r:    buildReq(http.MethodPost, "http://x", "application/json", body),
			cons: RequestConstraint{Body: map[string]interface{}{"a": "2"}},
			want: "body field a value mismatch",
		},
	}
	for _, tt := range tests {
		ok, reason := validateRequestReason(tt.r, tt.cons)
		if ok || !strings.Contains(reason, tt.want) {
			t.Errorf("%s: got (%v,%q) want contains %q", tt.name, ok, reason, tt.want)
		}
	}
}

func TestValidateRequestUnsupportedContentType(t *testing.T) {
	cons := RequestConstraint{Body: map[string]interface{}{"a": "b"}}
	r := buildReq(http.MethodPost, "http://x", "text/plain", []byte("ignored"))
	if !validateRequest(r, cons) {
		t.Fatal("expected success for unsupported content type")
	}
	if ok, reason := validateRequestReason(r, cons); !ok || reason != "" {
		t.Fatalf("expected empty reason on success, got %v %q", ok, reason)
	}

	r = buildReq(http.MethodPost, "http://x", "", []byte("ignored"))
	if !validateRequest(r, cons) {
		t.Fatal("expected success with no content type")
	}
}
