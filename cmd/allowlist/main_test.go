package main

import (
	"bytes"
	"flag"
	"fmt"
	yaml "gopkg.in/yaml.v3"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/winhowes/AuthTranslator/cmd/allowlist/plugins"
)

const fullAccessCapability = "dangerously_allow_full_access"

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

// helper to capture stderr from f
func captureStderr(f func()) string {
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	f()
	w.Close()
	os.Stderr = old
	data, _ := io.ReadAll(r)
	return string(data)
}

func TestAddEntryNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	addEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", fullAccessCapability})

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
				{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: fullAccessCapability, Params: nil}}},
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
		{Integration: "github", Callers: []plugins.CallerConfig{{ID: "u1"}}},
	}
	data, _ := yaml.Marshal(initial)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	addEntry([]string{"-integration", "github", "-caller", "u1", "-capability", "comment", "-params", "repo=org/repo"})

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
			Integration: "github",
			Callers:     []plugins.CallerConfig{{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "comment", Params: map[string]interface{}{"repo": "org/repo"}}}}},
		},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries mismatch:\n%v\nwant\n%v", entries, want)
	}
}

func TestAddEntryIntegrationCaseInsensitive(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	initial := []plugins.AllowlistEntry{
		{Integration: "Foo", Callers: []plugins.CallerConfig{{ID: "u1"}}},
	}
	data, _ := yaml.Marshal(initial)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	addEntry([]string{"-integration", "FOO", "-caller", "u1", "-capability", fullAccessCapability})

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
			Callers:     []plugins.CallerConfig{{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: fullAccessCapability, Params: nil}}}},
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
	if !strings.Contains(out, "post_as (params: username)") {
		t.Fatalf("missing capability info: %s", out)
	}
	if !strings.Contains(out, "post_channels_as (params: username,channels)") {
		t.Fatalf("missing capability info: %s", out)
	}
	if !strings.Contains(out, "post_channels (params: channels)") {
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

func TestRemoveEntryIntegrationCaseInsensitive(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	initial := []plugins.AllowlistEntry{
		{
			Integration: "Foo",
			Callers:     []plugins.CallerConfig{{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap1"}, {Name: "cap2"}}}},
		},
	}
	data, _ := yaml.Marshal(initial)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	removeEntry([]string{"-integration", "FOO", "-caller", "u1", "-capability", "cap1"})

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
			Callers:     []plugins.CallerConfig{{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap2"}}}},
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
				{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap1", Params: nil}}},
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

	addEntry([]string{"-integration", "foo", "-caller", "u2", "-capability", fullAccessCapability})

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
				{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap1", Params: nil}}},
				{ID: "u2", Capabilities: []plugins.CapabilityConfig{{Name: fullAccessCapability, Params: nil}}},
			},
		},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Logf("entries=%#v", entries)
		t.Logf("want=%#v", want)
		t.Fatalf("entries mismatch")
	}
}

func TestAddEntryDuplicateCapability(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	initial := []plugins.AllowlistEntry{
		{
			Integration: "github",
			Callers: []plugins.CallerConfig{
				{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "comment", Params: map[string]interface{}{"repo": "org/old"}}}},
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

	addEntry([]string{"-integration", "github", "-caller", "u1", "-capability", "comment", "-params", "repo=org/new"})

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
			Integration: "github",
			Callers: []plugins.CallerConfig{
				{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "comment", Params: map[string]interface{}{"repo": "org/new"}}}},
			},
		},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries mismatch:\n%v\nwant\n%v", entries, want)
	}
}

func TestAddEntryParamTrim(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	addEntry([]string{"-integration", "sendgrid", "-caller", "u1", "-capability", "send_email", "-params", "from=me@example.com, replyTo = reply@example.com "})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	params := entries[0].Callers[0].Capabilities[0].Params
	if params["from"] != "me@example.com" || params["replyTo"] != "reply@example.com" {
		t.Fatalf("params not trimmed: %#v", params)
	}
}

func TestAddEntryIgnoresEmptyParams(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")
	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	addEntry([]string{"-integration", "sendgrid", "-caller", "u1", "-capability", "send_email", "-params", "from=me@example.com,, ,replyTo=reply@example.com"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	params := entries[0].Callers[0].Capabilities[0].Params
	if len(params) != 2 || params["from"] != "me@example.com" || params["replyTo"] != "reply@example.com" {
		t.Fatalf("unexpected params: %#v", params)
	}
}

func TestAddEntryParsesStructuredParams(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")
	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	addEntry([]string{"-integration", "slack", "-caller", "u1", "-capability", "post_channels", "-params", `channels=["C123","C456"]`})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	params := entries[0].Callers[0].Capabilities[0].Params
	channels, ok := params["channels"].([]interface{})
	if !ok || len(channels) != 2 || channels[0] != "C123" || channels[1] != "C456" {
		t.Fatalf("channels not parsed as JSON array: %#v", params["channels"])
	}
}

func TestAddEntryRejectsMalformedParams(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")
	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	out := captureStderr(func() {
		addEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", fullAccessCapability, "-params", "repo"})
	})
	if !strings.Contains(out, "invalid param") {
		t.Fatalf("unexpected error output: %s", out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file should not be created")
	}
}

func TestParseParamsStructuredValues(t *testing.T) {
	params, err := parseParams(`repo=org/repo,object={"labels":["bug"]},quoted="a\"b",empty=,none=null,enabled=true,disabled=false`)
	if err != nil {
		t.Fatalf("parseParams failed: %v", err)
	}

	want := map[string]interface{}{
		"repo":     "org/repo",
		"object":   map[string]interface{}{"labels": []interface{}{"bug"}},
		"quoted":   `a"b`,
		"empty":    "",
		"none":     nil,
		"enabled":  true,
		"disabled": false,
	}
	if !reflect.DeepEqual(params, want) {
		t.Fatalf("params mismatch:\n%#v\nwant\n%#v", params, want)
	}
}

func TestParseParamsErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "invalid param", input: "repo", want: "invalid param"},
		{name: "invalid json", input: "channels=[broken]", want: "invalid value for param channels"},
		{name: "unmatched close", input: "channels=]", want: "unmatched"},
		{name: "unterminated quote", input: `text="unterminated`, want: "unterminated quoted value"},
		{name: "unmatched bracket", input: "channels=[", want: "unmatched bracket or brace"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseParams(tt.input)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestAddEntryRejectsUnknownCapability(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")
	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	out := captureStderr(func() {
		addEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", "missing"})
	})
	if !strings.Contains(out, "unknown capability missing") {
		t.Fatalf("unexpected error output: %s", out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file should not be created")
	}
}

func TestAddEntryRejectsInvalidCapabilityParam(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")
	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	out := captureStderr(func() {
		addEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", fullAccessCapability, "-params", "extra=value"})
	})
	if !strings.Contains(out, "unknown param extra") {
		t.Fatalf("unexpected error output: %s", out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file should not be created")
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

func TestRemoveEntrySkipsOtherCallers(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "allow.yaml")

	initial := []plugins.AllowlistEntry{
		{
			Integration: "foo",
			Callers: []plugins.CallerConfig{
				{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap1"}}},
				{ID: "u2", Capabilities: []plugins.CapabilityConfig{{Name: "cap2"}}},
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

	removeEntry([]string{"-integration", "foo", "-caller", "u2", "-capability", "cap2"})

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(out, &entries); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	want := []plugins.AllowlistEntry{
		{Integration: "foo", Callers: []plugins.CallerConfig{{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap1"}}}}},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries mismatch: %#v", entries)
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

// Helper process for exercising main() in a separate process
func TestAllowlistMainHelper(t *testing.T) {
	if os.Getenv("GO_WANT_ALLOWLIST_HELPER") != "1" {
		return
	}
	for i, a := range os.Args {
		if a == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	file = flag.CommandLine.String("file", "allowlist.yaml", "allowlist file")
	main()
	os.Exit(0)
}

func TestMainUnknownCommand(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestAllowlistMainHelper", "--", "badcmd")
	cmd.Env = append(os.Environ(), "GO_WANT_ALLOWLIST_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(string(out), "Usage: allowlist") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestAddEntryInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	os.WriteFile(path, []byte(":"), 0644)
	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	out := captureStderr(func() {
		addEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", fullAccessCapability})
	})
	if out == "" {
		t.Fatalf("expected error output")
	}
	data, _ := os.ReadFile(path)
	if string(data) != ":" {
		t.Fatalf("file changed")
	}
}

func TestAddEntryReadFileError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dir")
	os.Mkdir(path, 0755)
	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	out := captureStderr(func() {
		addEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", fullAccessCapability})
	})
	if out == "" {
		t.Fatalf("expected error output")
	}
}

func TestRemoveEntryMissingArgs(t *testing.T) {
	out := captureOutput(func() { removeEntry([]string{}) })
	if !strings.Contains(out, "-integration, -caller and -capability required") {
		t.Fatalf("missing error message")
	}
}

func TestMainAddRemoveCommands(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")

	oldFS := flag.CommandLine
	oldFile := file
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flag.CommandLine.SetOutput(os.Stdout)
	file = flag.CommandLine.String("file", path, "allowlist file")
	t.Cleanup(func() { flag.CommandLine = oldFS; file = oldFile })

	origArgs := os.Args
	os.Args = []string{"allowlist", "add", "-integration", "foo", "-caller", "u1", "-capability", fullAccessCapability}
	main()
	os.Args = []string{"allowlist", "remove", "-integration", "foo", "-caller", "u1", "-capability", fullAccessCapability}
	main()
	os.Args = origArgs

	data, _ := os.ReadFile(path)
	var entries []plugins.AllowlistEntry
	yaml.Unmarshal(data, &entries)
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %v", entries)
	}
}

// Helper process for exercising addEntry in a separate process
func TestAddEntryHelper(t *testing.T) {
	if os.Getenv("GO_WANT_ADD_HELPER") != "1" {
		return
	}
	cfg := os.Getenv("CFG")
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	file = flag.CommandLine.String("file", cfg, "allowlist file")
	addEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", fullAccessCapability})
	os.Exit(0)
}

func TestAddEntryWriteError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "no", "allow.yaml")
	cmd := exec.Command(os.Args[0], "-test.run=TestAddEntryHelper", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_ADD_HELPER=1", "CFG="+cfg)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(out) == 0 {
		t.Fatalf("expected error output")
	}
}

func TestAddEntryMarshalError(t *testing.T) {
	oldMarshal := yamlMarshal
	oldExit := exitFunc
	yamlMarshal = func(interface{}) ([]byte, error) {
		return nil, fmt.Errorf("marshal error")
	}
	exitFunc = func(code int) {
		panic(fmt.Sprintf("exit %d", code))
	}
	t.Cleanup(func() {
		yamlMarshal = oldMarshal
		exitFunc = oldExit
	})
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected exit")
		}
	}()

	addEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", fullAccessCapability})
}

func TestRemoveEntryMarshalError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	initial := []plugins.AllowlistEntry{{Integration: "foo", Callers: []plugins.CallerConfig{{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap"}}}}}}
	data, _ := yaml.Marshal(initial)
	os.WriteFile(path, data, 0644)

	oldMarshal := yamlMarshal
	oldExit := exitFunc
	oldFile := *file
	yamlMarshal = func(interface{}) ([]byte, error) {
		return nil, fmt.Errorf("marshal error")
	}
	exitFunc = func(code int) {
		panic(fmt.Sprintf("exit %d", code))
	}
	*file = path
	t.Cleanup(func() {
		yamlMarshal = oldMarshal
		exitFunc = oldExit
		*file = oldFile
	})
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected exit")
		}
	}()

	removeEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", "cap"})
}

func TestRemoveEntryWriteError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	initial := []plugins.AllowlistEntry{{Integration: "foo", Callers: []plugins.CallerConfig{{ID: "u1", Capabilities: []plugins.CapabilityConfig{{Name: "cap"}}}}}}
	data, _ := yaml.Marshal(initial)
	os.WriteFile(path, data, 0644)

	oldWrite := writeFile
	oldExit := exitFunc
	oldFile := *file
	writeFile = func(string, []byte, os.FileMode) error {
		return fmt.Errorf("write fail")
	}
	exitFunc = func(code int) {
		panic(fmt.Sprintf("exit %d", code))
	}
	*file = path
	t.Cleanup(func() {
		writeFile = oldWrite
		exitFunc = oldExit
		*file = oldFile
	})
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected exit")
		}
	}()

	removeEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", "cap"})
}

func TestRemoveEntryInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	os.WriteFile(path, []byte(":"), 0644)
	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	out := captureStderr(func() {
		removeEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", "c"})
	})
	if out == "" {
		t.Fatalf("expected error output")
	}
	data, _ := os.ReadFile(path)
	if string(data) != ":" {
		t.Fatalf("file changed")
	}
}

func TestRemoveEntryReadFileError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dir")
	os.Mkdir(path, 0755)
	old := *file
	*file = path
	t.Cleanup(func() { *file = old })

	out := captureStderr(func() {
		removeEntry([]string{"-integration", "foo", "-caller", "u1", "-capability", "c"})
	})
	if out == "" {
		t.Fatalf("expected error output")
	}
}

func TestMainNoArgs(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestAllowlistMainHelper", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_ALLOWLIST_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(string(out), "Usage: allowlist") {
		t.Fatalf("unexpected output: %s", out)
	}
}
