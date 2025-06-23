package integrationplugins

import (
	"errors"
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

	expanded := ExpandCapabilities("test", callers)

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

func TestExpandCapabilitiesUnknown(t *testing.T) {
	orig := capabilityRegistry
	t.Cleanup(func() { capabilityRegistry = orig })

	callers := []CallerConfig{{ID: "c", Capabilities: []CapabilityConfig{{Name: "unknown"}}}}
	res := ExpandCapabilities("test", callers)
	if len(res) != 1 || len(res[0].Rules) != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(res[0].Capabilities) != 0 {
		t.Fatalf("capabilities not cleared")
	}
}

func TestExpandCapabilitiesGenerateError(t *testing.T) {
	orig := capabilityRegistry
	capabilityRegistry = map[string]map[string]CapabilitySpec{}
	t.Cleanup(func() { capabilityRegistry = orig })
	RegisterCapability("e", "cap", CapabilitySpec{
		Generate: func(map[string]interface{}) ([]CallRule, error) { return nil, errors.New("boom") },
	})
	callers := []CallerConfig{{ID: "c", Capabilities: []CapabilityConfig{{Name: "cap"}}}}
	res := ExpandCapabilities("e", callers)
	if len(res) != 1 || len(res[0].Rules) != 0 {
		t.Fatalf("expected no rules on error")
	}
	if len(res[0].Capabilities) != 0 {
		t.Fatalf("capabilities not cleared")
	}
}

func TestCapabilitiesHelpers(t *testing.T) {
	// Save registry and restore after test
	orig := capabilityRegistry
	capabilityRegistry = map[string]map[string]CapabilitySpec{}
	t.Cleanup(func() { capabilityRegistry = orig })

	spec := CapabilitySpec{Generate: func(map[string]interface{}) ([]CallRule, error) { return nil, nil }}
	RegisterCapability("foo", "bar", spec)

	if got := CapabilitiesFor("foo"); len(got) != 1 || got["bar"].Generate == nil {
		t.Fatalf("CapabilitiesFor returned %#v", got)
	}

	all := AllCapabilities()
	if len(all) != 1 || len(all["foo"]) != 1 {
		t.Fatalf("AllCapabilities returned %#v", all)
	}
}

func TestExpandCapabilitiesGlobal(t *testing.T) {
	orig := capabilityRegistry
	capabilityRegistry = map[string]map[string]CapabilitySpec{}
	t.Cleanup(func() { capabilityRegistry = orig })

	RegisterCapability(GlobalIntegration, DangerouslyAllowFullAccess, CapabilitySpec{
		Generate: func(map[string]interface{}) ([]CallRule, error) {
			rule := CallRule{Path: "/**", Methods: map[string]RequestConstraint{"GET": {}}}
			return []CallRule{rule}, nil
		},
	})

	callers := []CallerConfig{{ID: "c", Capabilities: []CapabilityConfig{{Name: DangerouslyAllowFullAccess}}}}
	got := ExpandCapabilities("foo", callers)
	if len(got) != 1 || len(got[0].Rules) != 1 {
		t.Fatalf("unexpected expansion: %+v", got)
	}
	r := got[0].Rules[0]
	if r.Path != "/**" {
		t.Errorf("unexpected path %s", r.Path)
	}
	if _, ok := r.Methods["GET"]; !ok {
		t.Errorf("expected GET method in rule")
	}
}
