package plugins

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFilePluginLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("val\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	p := filePlugin{}
	got, err := p.Load(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "val" {
		t.Fatalf("expected 'val', got %s", got)
	}
}

func TestFilePluginLoadMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.txt")
	p := filePlugin{}
	if _, err := p.Load(context.Background(), path); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFilePluginLoadKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	contents := "# comment\nGH_SECRET=secret\nSLACK_SECRET = some_other_secret\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p := filePlugin{}
	got, err := p.Load(context.Background(), path+":SLACK_SECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "some_other_secret" {
		t.Fatalf("expected 'some_other_secret', got %s", got)
	}
}

func TestFilePluginLoadKeyMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(path, []byte("FOO=bar\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p := filePlugin{}
	if _, err := p.Load(context.Background(), path+":BAZ"); err == nil {
		t.Fatal("expected error when key missing")
	}
}
