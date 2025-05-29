package plugins

import (
	"context"
	"testing"
)

func TestEnvPluginLoad(t *testing.T) {
	t.Setenv("FOO", "bar")
	p := envPlugin{}
	got, err := p.Load(context.Background(), "FOO")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "bar" {
		t.Fatalf("expected 'bar', got %s", got)
	}
}

func TestEnvPluginLoadMissing(t *testing.T) {
	p := envPlugin{}
	if _, err := p.Load(context.Background(), "MISSING"); err == nil {
		t.Fatal("expected error for missing variable")
	}
}
