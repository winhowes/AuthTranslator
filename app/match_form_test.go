package main

import (
	"net/url"
	"strings"
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

func TestMatchQuerySuccess(t *testing.T) {
	vals := url.Values{"a": {"1", "2"}, "b": {"x"}}
	rule := map[string][]string{"a": {"1"}, "b": {"x"}}
	if !matchQuery(vals, rule) {
		t.Fatal("expected match")
	}
}

func TestMatchQueryMissingKey(t *testing.T) {
	vals := url.Values{"a": {"1"}}
	rule := map[string][]string{"a": {"1"}, "b": {"2"}}
	if matchQuery(vals, rule) {
		t.Fatal("expected missing key to fail")
	}
}

func TestMatchQueryMissingValue(t *testing.T) {
	vals := url.Values{"a": {"1"}, "b": {"x"}}
	rule := map[string][]string{"a": {"1", "2"}}
	if matchQuery(vals, rule) {
		t.Fatal("expected missing value to fail")
	}
}

func TestMatchValuePrimitive(t *testing.T) {
	if !matchValue("a", "a") {
		t.Fatal("expected primitive match")
	}
	if matchValue("a", "b") {
		t.Fatal("expected primitive mismatch")
	}
}

func TestMatchValueMap(t *testing.T) {
	data := map[string]interface{}{"a": "1", "b": "2"}
	rule := map[string]interface{}{"a": "1"}
	if !matchValue(data, rule) {
		t.Fatal("expected map match")
	}
	rule2 := map[string]interface{}{"c": "3"}
	if matchValue(data, rule2) {
		t.Fatal("expected missing key to fail")
	}
}

func TestMatchValueArray(t *testing.T) {
	data := []interface{}{"a", "b", "c"}
	rule := []interface{}{"a", "c"}
	if !matchValue(data, rule) {
		t.Fatal("expected array match")
	}
	rule2 := []interface{}{"a", "d"}
	if matchValue(data, rule2) {
		t.Fatal("expected array mismatch")
	}
}

func TestMatchValueNested(t *testing.T) {
	data := map[string]interface{}{
		"arr": []interface{}{
			map[string]interface{}{"x": "1"},
			map[string]interface{}{"x": "2"},
		},
	}
	rule := map[string]interface{}{
		"arr": []interface{}{
			map[string]interface{}{"x": "2"},
		},
	}
	if !matchValue(data, rule) {
		t.Fatal("expected nested match")
	}
}

func TestMatchFormReasonVariants(t *testing.T) {
	vals := url.Values{"a": {"1"}}

	if ok, reason := matchFormReason(vals, map[string]interface{}{"a": "1"}); !ok || reason != "" {
		t.Fatalf("expected success, got %v %q", ok, reason)
	}

	if ok, reason := matchFormReason(vals, map[string]interface{}{"b": "2"}); ok || !strings.Contains(reason, "missing form field b") {
		t.Fatalf("missing field: %v %q", ok, reason)
	}

	if ok, reason := matchFormReason(vals, map[string]interface{}{"a": []interface{}{"1", "2"}}); ok || !strings.Contains(reason, "form field a=2 not found") {
		t.Fatalf("missing value: %v %q", ok, reason)
	}

	if ok, reason := matchFormReason(vals, map[string]interface{}{"a": []interface{}{"1", 2}}); ok || reason != "invalid rule" {
		t.Fatalf("bad slice element: %v %q", ok, reason)
	}

	if ok, reason := matchFormReason(vals, map[string]interface{}{"a": 1}); ok || reason != "invalid rule" {
		t.Fatalf("bad type: %v %q", ok, reason)
	}
}
