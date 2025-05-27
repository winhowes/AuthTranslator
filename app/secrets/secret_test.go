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

func TestLoadRandomSecret(t *testing.T) {
	t.Setenv("A", "first")
	t.Setenv("B", "second")

	// Single reference
	val, err := LoadRandomSecret([]string{"env:A"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "first" {
		t.Fatalf("expected 'first', got %s", val)
	}

	// Multiple references - result should be one of the provided values
	val, err = LoadRandomSecret([]string{"env:A", "env:B"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "first" && val != "second" {
		t.Fatalf("unexpected value: %s", val)
	}
}
