package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// helper to create request preserving body
func req(method string, body []byte) *http.Request {
	r := httptest.NewRequest(method, "http://x", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestBodyArrayMatching(t *testing.T) {
	body := []byte(`{"arr":[1,2,3]}`)
	tests := []struct {
		name string
		rule map[string]interface{}
		want bool
	}{
		{
			name: "exact",
			rule: map[string]interface{}{"arr": []interface{}{float64(1), float64(2), float64(3)}},
			want: true,
		},
		{
			name: "subset",
			rule: map[string]interface{}{"arr": []interface{}{float64(1), float64(3)}},
			want: true,
		},
		{
			name: "unordered subset",
			rule: map[string]interface{}{"arr": []interface{}{float64(3), float64(1)}},
			want: true,
		},
		{
			name: "missing element",
			rule: map[string]interface{}{"arr": []interface{}{float64(1), float64(4)}},
			want: false,
		},
	}

	for _, tt := range tests {
		r := req(http.MethodPost, body)
		if got := validateRequest(r, RequestConstraint{Body: tt.rule}); got != tt.want {
			t.Errorf("%s: got %v want %v", tt.name, got, tt.want)
		}
	}
}

func TestBodyObjectMatching(t *testing.T) {
	body := []byte(`{"foo":"bar","num":1,"extra":true}`)
	tests := []struct {
		name string
		rule map[string]interface{}
		want bool
	}{
		{
			name: "exact",
			rule: map[string]interface{}{"foo": "bar", "num": float64(1), "extra": true},
			want: true,
		},
		{
			name: "subset",
			rule: map[string]interface{}{"foo": "bar"},
			want: true,
		},
		{
			name: "missing",
			rule: map[string]interface{}{"foo": "bar", "missing": "x"},
			want: false,
		},
	}
	for _, tt := range tests {
		r := req(http.MethodPost, body)
		if got := validateRequest(r, RequestConstraint{Body: tt.rule}); got != tt.want {
			t.Errorf("%s: got %v want %v", tt.name, got, tt.want)
		}
	}
}

func TestBodyNestedMatching(t *testing.T) {
	body := []byte(`{"obj":{"inner":"x","arr":[1,2]}}`)
	tests := []struct {
		name string
		rule map[string]interface{}
		want bool
	}{
		{
			name: "nested object",
			rule: map[string]interface{}{"obj": map[string]interface{}{"inner": "x"}},
			want: true,
		},
		{
			name: "nested array subset",
			rule: map[string]interface{}{"obj": map[string]interface{}{"arr": []interface{}{float64(2)}}},
			want: true,
		},
		{
			name: "nested fail",
			rule: map[string]interface{}{"obj": map[string]interface{}{"inner": "y"}},
			want: false,
		},
	}
	for _, tt := range tests {
		r := req(http.MethodPost, body)
		if got := validateRequest(r, RequestConstraint{Body: tt.rule}); got != tt.want {
			t.Errorf("%s: got %v want %v", tt.name, got, tt.want)
		}
	}
}

func TestBodyNumericTypeMismatch(t *testing.T) {
	body := []byte(`{"num":1}`)
	var rule map[string]interface{}
	if err := yaml.Unmarshal([]byte("num: 1"), &rule); err != nil {
		t.Fatal(err)
	}

	r := req(http.MethodPost, body)
	if !validateRequest(r, RequestConstraint{Body: rule}) {
		t.Fatal("expected numeric types to match")
	}
}
