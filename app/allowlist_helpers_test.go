package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
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
			cons:   RequestConstraint{Headers: []string{"X-Test"}},
			wantOK: true,
		},
		{
			name:   "header missing",
			r:      httptest.NewRequest(http.MethodGet, "http://x", nil),
			cons:   RequestConstraint{Headers: []string{"X-Test"}},
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
	}

	for _, tt := range tests {
		if got := validateRequest(tt.r, tt.cons); got != tt.wantOK {
			t.Errorf("%s: validateRequest=%v want %v", tt.name, got, tt.wantOK)
		}
	}
}
