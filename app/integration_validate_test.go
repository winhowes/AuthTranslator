package main

import (
	"strings"
	"testing"
)

type vrules []string

func (v vrules) RequiredParams() []string { return []string(v) }
func (v vrules) OptionalParams() []string { return nil }

type sample struct {
	A string `json:"a"`
	B int    `json:"b"`
}

func TestValidateRequiredOK(t *testing.T) {
	cfg := sample{A: "x", B: 1}
	if err := validateRequired(cfg, vrules{"a", "b"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateRequired(&cfg, vrules{"a", "b"}); err != nil {
		t.Fatalf("unexpected error for pointer: %v", err)
	}
}

func TestValidateRequiredMissing(t *testing.T) {
	cfg := sample{B: 1}
	err := validateRequired(cfg, vrules{"a", "b"})
	if err == nil || !strings.Contains(err.Error(), "missing param") {
		t.Fatalf("expected missing param error, got %v", err)
	}
}

func TestValidateRequiredUnknown(t *testing.T) {
	cfg := sample{A: "x", B: 1}
	err := validateRequired(cfg, vrules{"c"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func TestValidateRequiredNonStruct(t *testing.T) {
	err := validateRequired(42, vrules{"a"})
	if err == nil || !strings.Contains(err.Error(), "expected struct") {
		t.Fatalf("expected struct error, got %v", err)
	}
}

type taggedSample struct {
	Primary string   `json:",omitempty"`
	Named   string   `json:"named,omitempty"`
	Skip    []string `json:"-"`
}

func TestValidateRequiredTagParsing(t *testing.T) {
	cfg := taggedSample{Primary: "x", Named: "y", Skip: []string{"a"}}
	if err := validateRequired(cfg, vrules{"Primary", "named"}); err != nil {
		t.Fatalf("unexpected error validating tagged sample: %v", err)
	}
}
