package main

import (
	"reflect"
	"testing"
)

func TestBuildAllowlistMapValid(t *testing.T) {
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	entries := []AllowlistEntry{{
		Integration: "foo",
		Callers: []CallerConfig{
			{ID: "bar", Rules: []CallRule{{Path: "/x", Methods: map[string]RequestConstraint{"GET": {}}}}},
			{Rules: []CallRule{{Path: "/y", Methods: map[string]RequestConstraint{"POST": {}}}}},
		},
	}}

	if err := SetAllowlist("foo", entries[0].Callers); err != nil {
		t.Fatalf("SetAllowlist: %v", err)
	}

	allowlists.RLock()
	want := allowlists.m["foo"]
	allowlists.RUnlock()

	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	got, err := buildAllowlistMap(entries)
	if err != nil {
		t.Fatalf("buildAllowlistMap error: %v", err)
	}

	if !reflect.DeepEqual(got["foo"], want) {
		t.Fatalf("built map = %#v, want %#v", got["foo"], want)
	}

	allowlists.RLock()
	if len(allowlists.m) != 0 {
		allowlists.RUnlock()
		t.Fatal("global allowlist mutated")
	}
	allowlists.RUnlock()
}

func TestBuildAllowlistMapInvalid(t *testing.T) {
	entries := []AllowlistEntry{{
		Integration: "foo",
		Callers:     []CallerConfig{{ID: "a"}, {ID: "a"}},
	}}
	if _, err := buildAllowlistMap(entries); err == nil {
		t.Fatal("expected error for duplicate caller")
	}

	allowlists.RLock()
	if len(allowlists.m) != 0 {
		allowlists.RUnlock()
		t.Fatal("global allowlist mutated on error")
	}
	allowlists.RUnlock()
}
