package main

import (
	"strings"
	"testing"
)

func TestValidateDenylistEntriesDuplicateIntegration(t *testing.T) {
	entries := []DenylistEntry{{Integration: "a"}, {Integration: "a"}}
	if err := validateDenylistEntries(entries); err == nil {
		t.Fatal("expected duplicate integration error")
	}
}

func TestValidateDenylistEntriesMissingIntegration(t *testing.T) {
	entries := []DenylistEntry{{Integration: ""}}
	if err := validateDenylistEntries(entries); err == nil {
		t.Fatal("expected missing integration error")
	}
}

func TestValidateDenylistEntriesDuplicateCaller(t *testing.T) {
	entries := []DenylistEntry{{
		Integration: "dup",
		Callers:     []DenylistCaller{{ID: "a"}, {ID: "a"}},
	}}
	if err := validateDenylistEntries(entries); err == nil {
		t.Fatal("expected duplicate caller error")
	}
}

func TestValidateDenylistEntriesInvalidRule(t *testing.T) {
	entries := []DenylistEntry{{
		Integration: "test",
		Callers: []DenylistCaller{{
			ID:    "caller",
			Rules: []CallRule{{Methods: map[string]RequestConstraint{"GET": {}}}},
		}},
	}}
	if err := validateDenylistEntries(entries); err == nil {
		t.Fatal("expected invalid rule error")
	}
}

func TestValidateDenylistEntries(t *testing.T) {
	entries := []DenylistEntry{{
		Integration: "ok",
		Callers: []DenylistCaller{{
			ID: "*",
			Rules: []CallRule{{
				Path:    "/blocked",
				Methods: map[string]RequestConstraint{"GET": {}},
			}},
		}},
	}}
	if err := validateDenylistEntries(entries); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDenylistEntriesInvalidBodySchema(t *testing.T) {
	entries := []DenylistEntry{{
		Integration: "test",
		Callers: []DenylistCaller{{
			ID: "caller",
			Rules: []CallRule{{
				Path: "/blocked",
				Methods: map[string]RequestConstraint{
					"POST": {Body: map[string]interface{}{"type": "object", "properties": "bad"}},
				},
			}},
		}},
	}}
	err := validateDenylistEntries(entries)
	if err == nil || !strings.Contains(err.Error(), "invalid body schema") {
		t.Fatalf("expected invalid body schema error, got %v", err)
	}
}

func TestValidateDenylistEntriesLegacyBodyRejected(t *testing.T) {
	entries := []DenylistEntry{{
		Integration: "test",
		Callers: []DenylistCaller{{
			ID: "caller",
			Rules: []CallRule{{
				Path: "/blocked",
				Methods: map[string]RequestConstraint{
					"POST": {Body: map[string]interface{}{"text": "Hello"}},
				},
			}},
		}},
	}}
	err := validateDenylistEntries(entries)
	if err == nil || !strings.Contains(err.Error(), "body schema must use JSON Schema keywords") {
		t.Fatalf("expected legacy body schema error, got %v", err)
	}
}
