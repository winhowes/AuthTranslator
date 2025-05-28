package main

import (
	"testing"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrationplugins"
	_ "github.com/winhowes/AuthTranslator/app/integrationplugins/plugins"
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
