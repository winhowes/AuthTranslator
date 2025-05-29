package main

import (
	"bytes"
	"flag"
	yaml "gopkg.in/yaml.v3"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/winhowes/AuthTranslator/cmd/allowlist/plugins"
)

// helper to capture stdout from f
func captureOutput(f func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	old := os.Stdout
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestAddEntryNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	addEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", "cap"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		t.Fatalf("failed to parse yaml: %v", err)
	}
	want := []plugins.AllowlistEntry{
		{
			Integration: "foo",
			Callers: []plugins.CallerConfig{
				{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap", Params: map[string]interface{}{}}}},
			},
		},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries mismatch:\n%#v\nwant\n%#v", entries, want)
	}
}

func TestAddEntryUpdateExisting(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	initial := []plugins.AllowlistEntry{
		{Integration: "foo", Callers: []plugins.CallerConfig{{ID: "u1"}}},
	}
	data, _ := yaml.Marshal(initial)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	addEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", "cap2", "-params", "k=v"})

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(out, &entries); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	want := []plugins.AllowlistEntry{
		{
			Integration: "foo",
			Callers:     []plugins.CallerConfig{{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap2", Params: map[string]interface{}{"k": "v"}}}}},
		},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries mismatch:\n%v\nwant\n%v", entries, want)
	}
}

func TestListCapsOutput(t *testing.T) {
	out := captureOutput(listCaps)
	if !strings.Contains(out, "slack:") {
		t.Fatalf("missing slack integration in output: %s", out)
	}
	if !strings.Contains(out, "post_public_as (params: username)") {
		t.Fatalf("missing capability info: %s", out)
	}
	if !strings.Contains(out, "post_channels_as (params: username,channels)") {
		t.Fatalf("missing capability info: %s", out)
	}
}

func TestRemoveEntry(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	initial := []plugins.AllowlistEntry{
		{
			Integration: "foo",
			Callers: []plugins.CallerConfig{
				{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap1"}, {Name: "cap2"}}},
			},
		},
	}
	data, _ := yaml.Marshal(initial)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	removeEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", "cap1"})

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(out, &entries); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	want := []plugins.AllowlistEntry{
		{
			Integration: "foo",
			Callers: []plugins.CallerConfig{
				{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap2"}}},
			},
		},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries mismatch:\n%v\nwant\n%v", entries, want)
	}
}

func TestRemoveEntryDeletesCaller(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	initial := []plugins.AllowlistEntry{
		{
			Integration: "foo",
			Callers:     []plugins.CallerConfig{{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap1"}}}},
		},
	}
	data, _ := yaml.Marshal(initial)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	removeEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", "cap1"})

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(out, &entries); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	want := []plugins.AllowlistEntry{}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries mismatch:\n%v\nwant\n%v", entries, want)
	}
}

func TestAddEntryNewCaller(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	initial := []plugins.AllowlistEntry{
		{
			Integration: "foo",
			Callers: []plugins.CallerConfig{
				{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap1", Params: map[string]interface{}{}}}},
			},
		},
	}
	data, _ := yaml.Marshal(initial)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	addEntry([]string{"-integration", "foo", "-caller", "u2", "-capability", "cap2"})

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(out, &entries); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	want := []plugins.AllowlistEntry{
		{
			Integration: "foo",
			Callers: []plugins.CallerConfig{
				{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap1", Params: map[string]interface{}{}}}},
				{ID: "u2", Capabilities: []plugins.CapabilityConfig{{Name: "cap2", Params: map[string]interface{}{}}}},
			},
		},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Logf("entries=%#v", entries)
		t.Logf("want=%#v", want)
		t.Fatalf("entries mismatch")
	}
}

func TestAddEntryMissingArgs(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	out := captureOutput(func() { addEntry([]string{}) })
	if !strings.Contains(out, "-integration, -caller and -capability required") {
		t.Fatalf("missing error message: %s", out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file should not be created")
	}
}

func TestRemoveEntryIntegrationNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	initial := []plugins.AllowlistEntry{
		{
			Integration: "foo",
			Callers:     []plugins.CallerConfig{{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap1"}}}},
		},
	}
	data, _ := yaml.Marshal(initial)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	removeEntry([]string{"-integration", "bar", "-caller", "u1", "-capability", "cap1"})

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(out, &entries); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if !reflect.DeepEqual(entries, initial) {
		t.Fatalf("entries changed unexpectedly")
	}
}

func TestRemoveEntryCapabilityNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	initial := []plugins.AllowlistEntry{
		{
			Integration: "foo",
			Callers:     []plugins.CallerConfig{{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap1"}}}},
		},
	}
	data, _ := yaml.Marshal(initial)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	removeEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", "capX"})

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(out, &entries); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if !reflect.DeepEqual(entries, initial) {
		t.Fatalf("entries changed unexpectedly")
	}
}

func TestRemoveEntryFormatsParamsNull(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	initial := []plugins.AllowlistEntry{
		{
			Integration: "foo",
			Callers:     []plugins.CallerConfig{{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap1", Params: map[string]interface{}{}}}}},
		},
	}
	data, _ := yaml.Marshal(initial)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	removeEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", "missing"})

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	dataStr := string(out)
	if !strings.Contains(dataStr, "params: null") {
		t.Fatalf("expected params to be null, got: %s", dataStr)
	}
}

func TestUsageOutput(t *testing.T) {
	oldFS := flag.CommandLine
	oldFile := file
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	buf := &bytes.Buffer{}
	flag.CommandLine.SetOutput(buf)
	file = flag.CommandLine.String("file", "allowlist.yaml", "allowlist file")
	t.Cleanup(func() {
		flag.CommandLine = oldFS
		file = oldFile
	})

	usage()
	out := buf.String()
	if !strings.Contains(out, "Usage: allowlist") {
		t.Fatalf("usage output unexpected: %s", out)
	}
}

func TestMainListCommand(t *testing.T) {
	oldFS := flag.CommandLine
	oldFile := file
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flag.CommandLine.SetOutput(os.Stdout)
	file = flag.CommandLine.String("file", "allowlist.yaml", "allowlist file")
	t.Cleanup(func() {
		flag.CommandLine = oldFS
		file = oldFile
	})

	origArgs := os.Args
	os.Args = []string{"allowlist", "list"}
	defer func() { os.Args = origArgs }()

	out := captureOutput(main)
	if !strings.Contains(out, "slack:") {
		t.Fatalf("unexpected output: %s", out)
	}
}
