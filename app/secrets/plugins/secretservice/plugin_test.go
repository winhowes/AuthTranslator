package plugins

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestSecretServicePluginLoad(t *testing.T) {
	old := execSecretTool
	t.Cleanup(func() { execSecretTool = old })

	var gotArgs []string
	execSecretTool = func(ctx context.Context, args ...string) ([]byte, error) {
		gotArgs = append([]string{}, args...)
		return []byte("secret\n"), nil
	}

	p := secretServicePlugin{}
	got, err := p.Load(context.Background(), "service=slack,user=bot")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "secret\n" {
		t.Fatalf("expected exact secret bytes, got %q", got)
	}

	wantArgs := []string{"lookup", "service", "slack", "user", "bot"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("args = %v, want %v", gotArgs, wantArgs)
	}
}

func TestSecretServicePluginLoadPreservesWhitespace(t *testing.T) {
	old := execSecretTool
	t.Cleanup(func() { execSecretTool = old })

	execSecretTool = func(ctx context.Context, args ...string) ([]byte, error) {
		return []byte("  secret with spaces  \n"), nil
	}

	p := secretServicePlugin{}
	got, err := p.Load(context.Background(), "service=slack")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "  secret with spaces  \n" {
		t.Fatalf("expected exact secret bytes, got %q", got)
	}
}

func TestSecretServicePluginLoadPreservesCRLFTrailingBytes(t *testing.T) {
	old := execSecretTool
	t.Cleanup(func() { execSecretTool = old })

	execSecretTool = func(ctx context.Context, args ...string) ([]byte, error) {
		return []byte("secret\r\n"), nil
	}

	p := secretServicePlugin{}
	got, err := p.Load(context.Background(), "service=slack")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "secret\r\n" {
		t.Fatalf("expected exact secret bytes, got %q", got)
	}
}

func TestSecretServicePluginLoadInvalidID(t *testing.T) {
	p := secretServicePlugin{}
	if _, err := p.Load(context.Background(), "bad"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestSecretServicePluginLoadCommandError(t *testing.T) {
	old := execSecretTool
	t.Cleanup(func() { execSecretTool = old })

	execSecretTool = func(ctx context.Context, args ...string) ([]byte, error) {
		return nil, errors.New("secret-tool failed")
	}

	p := secretServicePlugin{}
	if _, err := p.Load(context.Background(), "service=slack"); err == nil {
		t.Fatal("expected command error")
	}
}

func TestParseSecretServiceAttrs(t *testing.T) {
	attrs, err := parseSecretServiceAttrs("service=slack,user=bot")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := [][2]string{{"service", "slack"}, {"user", "bot"}}
	if !reflect.DeepEqual(attrs, want) {
		t.Fatalf("attrs = %v, want %v", attrs, want)
	}
}

func TestExecSecretToolDefault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := execSecretTool(ctx, "lookup", "service", "unused"); err == nil {
		t.Fatal("expected error from canceled context")
	}
}

func TestParseSecretServiceAttrsErrors(t *testing.T) {
	cases := []string{"", "missingequals", "=value", "key="}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, err := parseSecretServiceAttrs(tc); err == nil {
				t.Fatalf("expected error for %q", tc)
			}
		})
	}
}
