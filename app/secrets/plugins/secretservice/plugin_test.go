package plugins

import (
	"context"
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
	if got != "secret" {
		t.Fatalf("expected secret, got %q", got)
	}

	wantArgs := []string{"lookup", "service", "slack", "user", "bot"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("args = %v, want %v", gotArgs, wantArgs)
	}
}

func TestSecretServicePluginLoadInvalidID(t *testing.T) {
	p := secretServicePlugin{}
	if _, err := p.Load(context.Background(), "bad"); err == nil {
		t.Fatal("expected parse error")
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
