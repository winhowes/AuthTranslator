package plugins

import (
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
	got, err := p.Load(path)
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
	if _, err := p.Load(path); err == nil {
		t.Fatal("expected error for missing file")
	}
}
