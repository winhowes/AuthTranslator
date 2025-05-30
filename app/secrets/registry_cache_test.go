package secrets_test

import (
	"context"
	"testing"
	"time"

	"github.com/winhowes/AuthTranslator/app/secrets"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestClearCache(t *testing.T) {
	t.Setenv("CACHE_SECRET", "first")
	val, err := secrets.LoadSecret(context.Background(), "env:CACHE_SECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "first" {
		t.Fatalf("expected 'first', got %s", val)
	}

	// Change the underlying secret; cache should still return old value.
	t.Setenv("CACHE_SECRET", "second")
	if val, err := secrets.LoadSecret(context.Background(), "env:CACHE_SECRET"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	} else if val != "first" {
		t.Fatalf("expected cached 'first', got %s", val)
	}

	secrets.ClearCache()

	val, err = secrets.LoadSecret(context.Background(), "env:CACHE_SECRET")
	if err != nil {
		t.Fatalf("unexpected error after clear: %v", err)
	}
	if val != "second" {
		t.Fatalf("expected 'second' after clear, got %s", val)
	}
}

func TestCacheTTL(t *testing.T) {
	defer secrets.ClearCache()
	old := secrets.CacheTTL
	secrets.CacheTTL = 50 * time.Millisecond
	defer func() { secrets.CacheTTL = old }()

	ctx := context.Background()
	t.Setenv("TTL_SECRET", "first")

	val, err := secrets.LoadSecret(ctx, "env:TTL_SECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "first" {
		t.Fatalf("expected 'first', got %s", val)
	}

	// Change underlying secret; cached value should persist until expiry.
	t.Setenv("TTL_SECRET", "second")
	if val, err := secrets.LoadSecret(ctx, "env:TTL_SECRET"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	} else if val != "first" {
		t.Fatalf("expected cached 'first', got %s", val)
	}

	time.Sleep(60 * time.Millisecond)

	val, err = secrets.LoadSecret(ctx, "env:TTL_SECRET")
	if err != nil {
		t.Fatalf("unexpected error after ttl: %v", err)
	}
	if val != "second" {
		t.Fatalf("expected 'second' after ttl, got %s", val)
	}
}
