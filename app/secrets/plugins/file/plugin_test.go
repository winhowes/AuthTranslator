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

func TestFilePluginLoadKeySkipsNonMatching(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	contents := "# comment about the file\nIGNORED\nFOO=  value with space  \nBAR=bar\nFOO=second\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p := filePlugin{}
	got, err := p.Load(context.Background(), path+":FOO")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "value with space" {
		t.Fatalf("expected trimmed value, got %q", got)
	}
}

func TestFilePluginLoadKeyScannerError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	// Create a single extremely long line so bufio.Scanner hits ErrTooLong.
	longLine := make([]byte, 70_000)
	for i := range longLine {
		longLine[i] = 'A'
	}
	if err := os.WriteFile(path, append(longLine, '\n'), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p := filePlugin{}
	if _, err := p.Load(context.Background(), path+":FOO"); err == nil {
		t.Fatal("expected scanner error for oversized line")
	}
}

func TestSplitPathAndKey(t *testing.T) {
	tests := map[string]struct {
		input string
		wantP string
		wantK string
	}{
		"no suffix":             {input: "/tmp/secret", wantP: "/tmp/secret", wantK: ""},
		"with key":              {input: "/tmp/secret:FOO", wantP: "/tmp/secret", wantK: "FOO"},
		"colon but empty":       {input: "/tmp/secret:", wantP: "/tmp/secret:", wantK: ""},
		"suffix has slash":      {input: "/tmp/secret:sub/path", wantP: "/tmp/secret:sub/path", wantK: ""},
		"windows path":          {input: `C:\\secrets\\file`, wantP: `C:\\secrets\\file`, wantK: ""},
		"windows path with key": {input: `C:\\secrets\\file:FOO`, wantP: `C:\\secrets\\file`, wantK: "FOO"},
		"multiple colons":       {input: "/tmp/a:b:c", wantP: "/tmp/a:b", wantK: "c"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotP, gotK := splitPathAndKey(tc.input)
			if gotP != tc.wantP || gotK != tc.wantK {
				t.Fatalf("splitPathAndKey(%q) = (%q,%q), want (%q,%q)", tc.input, gotP, gotK, tc.wantP, tc.wantK)
			}
		})
	}
}
