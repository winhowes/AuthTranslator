package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIListDeleteUpdate(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")

	// add
	out, err := exec.Command("go", "run", ".", "-file", cfg, "slack", "-token", "t", "-signing-secret", "s").CombinedOutput()
	if err != nil {
		t.Fatalf("add failed: %v\n%s", err, out)
	}

	// list
	out, err = exec.Command("go", "run", ".", "-file", cfg, "list").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "slack") {
		t.Fatalf("list failed: %v\n%s", err, out)
	}

	// update
	out, err = exec.Command("go", "run", ".", "-file", cfg, "update", "slack", "-token", "t2", "-signing-secret", "s2").CombinedOutput()
	if err != nil {
		t.Fatalf("update failed: %v\n%s", err, out)
	}

	// delete
	out, err = exec.Command("go", "run", ".", "-file", cfg, "delete", "slack").CombinedOutput()
	if err != nil {
		t.Fatalf("delete failed: %v\n%s", err, out)
	}
}
