package main

import (
	"net/url"
	"testing"
)

func TestMatchForm(t *testing.T) {
	vals := url.Values{"a": {"1", "2"}, "b": {"x"}}
	rule := map[string]interface{}{"a": []interface{}{"1"}, "b": "x"}
	if !matchForm(vals, rule) {
		t.Fatal("expected match")
	}
}

func TestMatchFormMissingKey(t *testing.T) {
	vals := url.Values{"a": {"1"}}
	rule := map[string]interface{}{"b": "x"}
	if matchForm(vals, rule) {
		t.Fatal("expected missing key to fail")
	}
}

func TestMatchFormMissingValue(t *testing.T) {
	vals := url.Values{"a": {"1"}}
	rule := map[string]interface{}{"a": []interface{}{"1", "2"}}
	if matchForm(vals, rule) {
		t.Fatal("expected missing value to fail")
	}
}

func TestMatchFormNonString(t *testing.T) {
	vals := url.Values{"a": {"1"}}
	rule := map[string]interface{}{"a": []interface{}{1}}
	if matchForm(vals, rule) {
		t.Fatal("expected non-string to fail")
	}
}

func TestMatchFormStringValue(t *testing.T) {
	vals := url.Values{"a": {"1"}}
	rule := map[string]interface{}{"a": "1"}
	if !matchForm(vals, rule) {
		t.Fatal("expected string value match")
	}
	rule = map[string]interface{}{"a": "2"}
	if matchForm(vals, rule) {
		t.Fatal("expected string value mismatch to fail")
	}
}

func TestMatchFormInvalidType(t *testing.T) {
	vals := url.Values{"a": {"1"}}
	rule := map[string]interface{}{"a": 1}
	if matchForm(vals, rule) {
		t.Fatal("expected invalid type to fail")
	}
}
