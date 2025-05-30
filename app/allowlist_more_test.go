package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
