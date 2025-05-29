package secrets_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/winhowes/AuthTranslator/app/secrets"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestLoadSecretFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("top-secret"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	val, err := secrets.LoadSecret(context.Background(), "file:"+path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "top-secret" {
		t.Fatalf("expected 'top-secret', got %s", val)
	}
}

func TestLoadSecretFileTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("top-secret\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	val, err := secrets.LoadSecret(context.Background(), "file:"+path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "top-secret" {
		t.Fatalf("expected 'top-secret', got %s", val)
	}
}

func TestLoadSecretFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.txt")
	if _, err := secrets.LoadSecret(context.Background(), "file:"+path); err == nil {
		t.Fatal("expected error for missing file")
	}
}
