package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins"
)

func TestValidateAllowlistEntriesDuplicateIntegration(t *testing.T) {
	entries := []AllowlistEntry{{Integration: "a"}, {Integration: "a"}}
	if err := validateAllowlistEntries(entries); err == nil {
		t.Fatal("expected error for duplicate integration")
	}
}

func TestValidateAllowlistEntriesUnknownCapability(t *testing.T) {
	entries := []AllowlistEntry{{
		Integration: "slack",
		Callers:     []CallerConfig{{ID: "c", Capabilities: []integrationplugins.CapabilityConfig{{Name: "bogus"}}}},
	}}
	if err := validateAllowlistEntries(entries); err == nil {
		t.Fatal("expected error for unknown capability")
	}
}

func TestValidateAllowlistEntriesInvalidRule(t *testing.T) {
	entries := []AllowlistEntry{{
		Integration: "test",
		Callers:     []CallerConfig{{ID: "c", Rules: []CallRule{{Path: "/x", Methods: map[string]RequestConstraint{}}}}},
	}}
	if err := validateAllowlistEntries(entries); err == nil {
		t.Fatal("expected error for empty methods")
	}
}

func TestValidateAllowlistEntriesDuplicateCaller(t *testing.T) {
	entries := []AllowlistEntry{{
		Integration: "test",
		Callers:     []CallerConfig{{ID: "a"}, {ID: "a"}},
	}}
	if err := validateAllowlistEntries(entries); err == nil {
		t.Fatal("expected error for duplicate caller")
	}
}

func TestValidateAllowlistEntriesMissingIntegration(t *testing.T) {
	entries := []AllowlistEntry{{Integration: ""}}
	err := validateAllowlistEntries(entries)
	if err == nil || !strings.Contains(err.Error(), "missing integration") {
		t.Fatalf("expected missing integration error, got %v", err)
	}
}

func TestValidateAllowlistEntriesNoRulesOrCapabilities(t *testing.T) {
	entries := []AllowlistEntry{{
		Integration: "test",
		Callers:     []CallerConfig{{ID: "c"}},
	}}
	if err := validateAllowlistEntries(entries); err == nil {
		t.Fatal("expected error for caller with no rules or capabilities")
	}
}

func TestValidateAllowlistEntriesMissingPath(t *testing.T) {
	entries := []AllowlistEntry{{
		Integration: "test",
		Callers:     []CallerConfig{{ID: "c", Rules: []CallRule{{Path: " ", Methods: map[string]RequestConstraint{"GET": {}}}}}},
	}}
	if err := validateAllowlistEntries(entries); err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestValidateAllowlistEntriesMethodCaseIgnored(t *testing.T) {
	entries := []AllowlistEntry{{
		Integration: "test",
		Callers:     []CallerConfig{{ID: "c", Rules: []CallRule{{Path: "/x", Methods: map[string]RequestConstraint{"get": {}}}}}},
	}}
	if err := validateAllowlistEntries(entries); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAllowlistEntriesCapabilityParamErrors(t *testing.T) {
	entries := []AllowlistEntry{{
		Integration: "slack",
		Callers: []CallerConfig{{
			ID: "c",
			Capabilities: []integrationplugins.CapabilityConfig{{
                               Name:   "post_as",
				Params: map[string]interface{}{"username": "u", "extra": "bad"},
			}},
		}},
	}}
	if err := validateAllowlistEntries(entries); err == nil {
		t.Fatal("expected error for unknown capability param")
	}

	entries = []AllowlistEntry{{
		Integration: "slack",
		Callers: []CallerConfig{{
			ID: "c",
			Capabilities: []integrationplugins.CapabilityConfig{{
                               Name:   "post_as",
				Params: map[string]interface{}{"username": ""},
			}},
		}},
	}}
	if err := validateAllowlistEntries(entries); err == nil {
		t.Fatal("expected error for invalid capability params")
	}
}

func TestValidateAllowlistEntriesDuplicateRule(t *testing.T) {
	entries := []AllowlistEntry{{
		Integration: "test",
		Callers: []CallerConfig{{
			ID: "c",
			Rules: []CallRule{
				{Path: "/x", Methods: map[string]RequestConstraint{"GET": {}}},
				{Path: "/x", Methods: map[string]RequestConstraint{"GET": {}}},
			},
		}},
	}}
	if err := validateAllowlistEntries(entries); err == nil {
		t.Fatal("expected error for duplicate rule")
	}
}

func TestValidateAllowlistEntriesDuplicateWildcardCaller(t *testing.T) {
	entries := []AllowlistEntry{{
		Integration: "test",
		Callers: []CallerConfig{
			{ID: "*", Rules: []CallRule{{Path: "/a", Methods: map[string]RequestConstraint{"GET": {}}}}},
			{ID: "", Rules: []CallRule{{Path: "/b", Methods: map[string]RequestConstraint{"POST": {}}}}},
		},
	}}
	if err := validateAllowlistEntries(entries); err == nil {
		t.Fatal("expected error for duplicate caller id")
	}
}

func TestValidateAllowlistEntriesDoesNotModifyInput(t *testing.T) {
	// snapshot existing registry and restore after test
	orig := make(map[string]map[string]integrationplugins.CapabilitySpec)
	for integ, caps := range integrationplugins.AllCapabilities() {
		m := make(map[string]integrationplugins.CapabilitySpec, len(caps))
		for name, spec := range caps {
			m[name] = spec
		}
		orig[integ] = m
	}
	t.Cleanup(func() {
		reg := integrationplugins.AllCapabilities()
		for k := range reg {
			delete(reg, k)
		}
		for k, v := range orig {
			reg[k] = v
		}
	})

	integrationplugins.RegisterCapability("copytest", "cap", integrationplugins.CapabilitySpec{
		Generate: func(map[string]interface{}) ([]integrationplugins.CallRule, error) {
			return []integrationplugins.CallRule{{Path: "/x", Methods: map[string]integrationplugins.RequestConstraint{"GET": {}}}}, nil
		},
	})
	original := []AllowlistEntry{{
		Integration: "copytest",
		Callers:     []CallerConfig{{ID: "c", Capabilities: []integrationplugins.CapabilityConfig{{Name: "cap"}}}},
	}}

	// Make a deep copy to detect modifications
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	var entries []AllowlistEntry
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}

	if err := validateAllowlistEntries(entries); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(entries, original) {
		t.Fatalf("input modified: %#v", entries)
	}
}
