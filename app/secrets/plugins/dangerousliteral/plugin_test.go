package plugins

import (
	"context"
	"testing"
)

func TestDangerousLiteralPluginPrefix(t *testing.T) {
	p := dangerousLiteralPlugin{}
	if got, want := p.Prefix(), "dangerousLiteral"; got != want {
		t.Fatalf("Prefix() = %q, want %q", got, want)
	}
}

func TestDangerousLiteralPluginLoad(t *testing.T) {
	ctx := context.Background()
	p := dangerousLiteralPlugin{}
	want := "literal-value"
	got, err := p.Load(ctx, want)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("Load() = %q, want %q", got, want)
	}
}
