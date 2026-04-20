package plugins

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
)

func TestKeychainPluginLoad(t *testing.T) {
	old := execSecurityCommand
	t.Cleanup(func() { execSecurityCommand = old })

	var gotArgs []string
	execSecurityCommand = func(ctx context.Context, args ...string) ([]byte, error) {
		gotArgs = append([]string{}, args...)
		return []byte("super-secret\n"), nil
	}

	p := keychainPlugin{}
	got, err := p.Load(context.Background(), "slack#bot")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "super-secret" {
		t.Fatalf("expected trimmed secret, got %q", got)
	}

	wantArgs := []string{"find-generic-password", "-w", "-s", "slack", "-a", "bot"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("args = %v, want %v", gotArgs, wantArgs)
	}
}

func TestKeychainPluginLoadServiceOnly(t *testing.T) {
	old := execSecurityCommand
	t.Cleanup(func() { execSecurityCommand = old })

	var gotArgs []string
	execSecurityCommand = func(ctx context.Context, args ...string) ([]byte, error) {
		gotArgs = append([]string{}, args...)
		return []byte("token"), nil
	}

	p := keychainPlugin{}
	if _, err := p.Load(context.Background(), "slack"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantArgs := []string{"find-generic-password", "-w", "-s", "slack"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("args = %v, want %v", gotArgs, wantArgs)
	}
}

func TestKeychainPluginLoadMissingService(t *testing.T) {
	p := keychainPlugin{}
	if _, err := p.Load(context.Background(), "   "); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestKeychainPluginLoadExitError(t *testing.T) {
	old := execSecurityCommand
	t.Cleanup(func() { execSecurityCommand = old })

	execSecurityCommand = func(ctx context.Context, args ...string) ([]byte, error) {
		return nil, &exec.ExitError{Stderr: []byte("item not found")}
	}

	p := keychainPlugin{}
	if _, err := p.Load(context.Background(), "missing"); err == nil {
		t.Fatal("expected lookup error")
	}
}

func TestKeychainPluginLoadExitErrorNoStderr(t *testing.T) {
	old := execSecurityCommand
	t.Cleanup(func() { execSecurityCommand = old })

	execSecurityCommand = func(ctx context.Context, args ...string) ([]byte, error) {
		return nil, &exec.ExitError{}
	}

	p := keychainPlugin{}
	if _, err := p.Load(context.Background(), "missing"); err == nil {
		t.Fatal("expected lookup error")
	}
}

func TestKeychainPluginLoadCommandError(t *testing.T) {
	old := execSecurityCommand
	t.Cleanup(func() { execSecurityCommand = old })

	execSecurityCommand = func(ctx context.Context, args ...string) ([]byte, error) {
		return nil, errors.New("command missing")
	}

	p := keychainPlugin{}
	if _, err := p.Load(context.Background(), "service"); err == nil {
		t.Fatal("expected lookup error")
	}
}

func TestParseKeychainID(t *testing.T) {
	service, account := parseKeychainID("svc#acc")
	if service != "svc" || account != "acc" {
		t.Fatalf("unexpected parse result: %q %q", service, account)
	}

	service, account = parseKeychainID("svc-only")
	if service != "svc-only" || account != "" {
		t.Fatalf("unexpected parse result: %q %q", service, account)
	}

	service, account = parseKeychainID("  svc  #  acc  ")
	if service != "svc" || account != "acc" {
		t.Fatalf("unexpected trimmed parse result: %q %q", service, account)
	}
}
