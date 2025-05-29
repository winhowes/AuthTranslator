package main

import (
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
