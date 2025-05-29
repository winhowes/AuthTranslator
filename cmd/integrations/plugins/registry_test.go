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
