package secrets

import "testing"

func TestLoadSecretEnv(t *testing.T) {
	t.Setenv("MY_SECRET", "val")
	s, err := LoadSecret("env:MY_SECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s != "val" {
		t.Fatalf("expected 'val', got %s", s)
	}
}

func TestLoadSecretUnknown(t *testing.T) {
	if _, err := LoadSecret("unknown:id"); err == nil {
		t.Fatal("expected error for unknown secret source")
	}
}
