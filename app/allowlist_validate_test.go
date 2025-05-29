package main

import (
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

func TestValidateAllowlistEntriesInvalidMethodCase(t *testing.T) {
	entries := []AllowlistEntry{{
		Integration: "test",
		Callers:     []CallerConfig{{ID: "c", Rules: []CallRule{{Path: "/x", Methods: map[string]RequestConstraint{"get": {}}}}}},
	}}
	if err := validateAllowlistEntries(entries); err == nil {
		t.Fatal("expected error for invalid method case")
	}
}

func TestValidateAllowlistEntriesCapabilityParamErrors(t *testing.T) {
	entries := []AllowlistEntry{{
		Integration: "slack",
		Callers: []CallerConfig{{
			ID: "c",
			Capabilities: []integrationplugins.CapabilityConfig{{
				Name:   "post_public_as",
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
				Name:   "post_public_as",
				Params: map[string]interface{}{"username": ""},
			}},
		}},
	}}
	if err := validateAllowlistEntries(entries); err == nil {
		t.Fatal("expected error for invalid capability params")
	}
}
