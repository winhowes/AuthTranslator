package secrets_test

import (
	"testing"

	"github.com/winhowes/AuthTranslator/app/secrets"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestClearCache(t *testing.T) {
	t.Setenv("CACHE_SECRET", "first")
	val, err := secrets.LoadSecret("env:CACHE_SECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "first" {
		t.Fatalf("expected 'first', got %s", val)
	}

	// Change the underlying secret; cache should still return old value.
	t.Setenv("CACHE_SECRET", "second")
	if val, err := secrets.LoadSecret("env:CACHE_SECRET"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	} else if val != "first" {
		t.Fatalf("expected cached 'first', got %s", val)
	}

	secrets.ClearCache()

	val, err = secrets.LoadSecret("env:CACHE_SECRET")
	if err != nil {
		t.Fatalf("unexpected error after clear: %v", err)
	}
	if val != "second" {
		t.Fatalf("expected 'second' after clear, got %s", val)
	}
}
