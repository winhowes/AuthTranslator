package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// helper to create request preserving body
func req(method string, body []byte) *http.Request {
	r := httptest.NewRequest(method, "http://x", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestBodySchemaPattern(t *testing.T) {
	body := []byte(`{"channel":"allowed-test"}`)
	rule := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"channel": map[string]interface{}{
				"type":    "string",
				"pattern": "^allowed-",
			},
		},
		"required": []interface{}{"channel"},
	}

	r := req(http.MethodPost, body)
	if !validateRequest(r, RequestConstraint{Body: rule}) {
		t.Fatal("expected pattern to match")
	}

	r2 := req(http.MethodPost, []byte(`{"channel":"blocked"}`))
	if validateRequest(r2, RequestConstraint{Body: rule}) {
		t.Fatal("expected pattern mismatch to fail")
	}
}

func TestBodySchemaRange(t *testing.T) {
	body := []byte(`{"limit":10}`)
	rule := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"limit": map[string]interface{}{
				"type":    "integer",
				"minimum": 1,
				"maximum": 100,
			},
		},
		"required": []interface{}{"limit"},
	}

	r := req(http.MethodPost, body)
	if !validateRequest(r, RequestConstraint{Body: rule}) {
		t.Fatal("expected range to match")
	}

	r2 := req(http.MethodPost, []byte(`{"limit":200}`))
	if validateRequest(r2, RequestConstraint{Body: rule}) {
		t.Fatal("expected range mismatch to fail")
	}
}

func TestBodySchemaMinLength(t *testing.T) {
	body := []byte(`{"query":"hi"}`)
	rule := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"query": map[string]interface{}{
				"type":      "string",
				"minLength": 1,
			},
		},
		"required": []interface{}{"query"},
	}

	r := req(http.MethodPost, body)
	if !validateRequest(r, RequestConstraint{Body: rule}) {
		t.Fatal("expected minLength to match")
	}

	r2 := req(http.MethodPost, []byte(`{"query":""}`))
	if validateRequest(r2, RequestConstraint{Body: rule}) {
		t.Fatal("expected minLength mismatch to fail")
	}
}
