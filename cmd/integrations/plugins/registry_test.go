package plugins

import "testing"

func TestListReturnsAllRegisteredNames(t *testing.T) {
	names := List()
	if len(names) != len(registry) {
		t.Fatalf("expected %d names, got %d", len(registry), len(names))
	}
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if seen[n] {
			t.Errorf("duplicate name %s", n)
		}
		seen[n] = true
	}
	for want := range registry {
		if !seen[want] {
			t.Errorf("missing name %s", want)
		}
	}
}

func TestRegisterAndGet(t *testing.T) {
	dummy := func(args []string) (Integration, error) { return Integration{Name: "dummy"}, nil }
	Register("dummy", dummy)
	if Get("dummy") == nil {
		t.Fatalf("registered builder not found")
	}
	found := false
	for _, n := range List() {
		if n == "dummy" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dummy not listed")
	}
	delete(registry, "dummy")
}
