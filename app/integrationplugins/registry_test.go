package integrationplugins

import (
	"fmt"
	"testing"
)

func TestExpandCapabilities(t *testing.T) {
	// Save current registry state and restore after test
	orig := capabilityRegistry
	t.Cleanup(func() { capabilityRegistry = orig })

	// Register a simple capability for integration "test"
	RegisterCapability("test", "cap", CapabilitySpec{
		Generate: func(params map[string]interface{}) ([]CallRule, error) {
			rule := CallRule{Path: "/x", Methods: map[string]RequestConstraint{"GET": {}}}
			return []CallRule{rule}, nil
		},
	})

	callers := []CallerConfig{{
		ID:           "c1",
		Capabilities: []CapabilityConfig{{Name: "cap"}},
	}}

	expanded, err := ExpandCapabilities("test", callers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(expanded) != 1 {
		t.Fatalf("expected one caller, got %d", len(expanded))
	}
	got := expanded[0]
	if len(got.Rules) != 1 {
		t.Fatalf("expected one rule, got %d", len(got.Rules))
	}
	rule := got.Rules[0]
	if rule.Path != "/x" {
		t.Errorf("expected rule path '/x', got %s", rule.Path)
	}
	if _, ok := rule.Methods["GET"]; !ok {
		t.Errorf("expected GET method in rule")
	}
	if len(got.Capabilities) != 0 {
		t.Errorf("expected capabilities to be cleared")
	}
}

func TestExpandCapabilitiesError(t *testing.T) {
	orig := capabilityRegistry
	t.Cleanup(func() { capabilityRegistry = orig })

	RegisterCapability("err", "bad", CapabilitySpec{
		Generate: func(params map[string]interface{}) ([]CallRule, error) {
			return nil, fmt.Errorf("boom")
		},
	})

	callers := []CallerConfig{{
		ID:           "x",
		Capabilities: []CapabilityConfig{{Name: "bad"}},
	}}

	_, err := ExpandCapabilities("err", callers)
	if err == nil {
		t.Fatal("expected error for capability failure")
	}
	if len(callers[0].Capabilities) != 1 || len(callers[0].Rules) != 0 {
		t.Fatal("input callers modified on error")
	}
}
