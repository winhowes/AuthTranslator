package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/winhowes/AuthTranslator/cmd/integrations/plugins"
)

func TestAddUpdateDeleteList(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	old := *file
	*file = cfgFile
	t.Cleanup(func() { *file = old })

	// add
	addIntegration(plugins.Integration{Name: "foo"})

	list := captureList(t)
	if len(list) != 1 || list[0] != "foo" {
		t.Fatalf("unexpected list after add: %v", list)
	}

	// update
	updateIntegration(plugins.Integration{Name: "foo", Destination: "https://x"})

	list = captureList(t)
	if len(list) != 1 || list[0] != "foo" {
		t.Fatalf("unexpected list after update: %v", list)
	}

	// delete
	deleteIntegration("foo")

	list = captureList(t)
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %v", list)
	}
}

func captureList(t *testing.T) []string {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	listIntegrations()
	w.Close()
	os.Stdout = old
	data, _ := io.ReadAll(r)
	out := string(data)
	if out == "" {
		return nil
	}
	var res []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		res = append(res, line)
	}
	return res
}

func captureOutput(f func()) string {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	data, _ := io.ReadAll(r)
	return string(data)
}

// Helper process for exercising main() in a separate process.
func TestMainHelper(t *testing.T) {
	if os.Getenv("GO_WANT_INTEGRATIONS_HELPER") != "1" {
		return
	}
	for i, a := range os.Args {
		if a == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			break
		}
	}
	// Recreate flag set so we can parse arguments.
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	main()
	os.Exit(0)
}

func TestMainUnknownPlugin(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper", "--", "unknown")
	cmd.Env = append(os.Environ(), "GO_WANT_INTEGRATIONS_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(string(out), "unknown plugin unknown") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestReadConfigNonexistent(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.yaml")
	old := *file
	*file = cfg
	t.Cleanup(func() { *file = old })
	list, err := readConfig()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list")
	}
}

func TestReadConfigInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(cfg, []byte(":"), 0644)
	old := *file
	*file = cfg
	t.Cleanup(func() { *file = old })
	if _, err := readConfig(); err == nil {
		t.Fatalf("expected error")
	}
}

func TestReadConfigError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.yaml")
	os.Mkdir(cfg, 0755)
	old := *file
	*file = cfg
	t.Cleanup(func() { *file = old })
	if _, err := readConfig(); err == nil {
		t.Fatalf("expected error")
	}
}

func TestWriteConfigError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no", "cfg.yaml")
	old := *file
	*file = path
	t.Cleanup(func() { *file = old })
	err := writeConfig([]plugins.Integration{{Name: "x"}})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestUpdateIntegrationAddsNew(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.yaml")
	old := *file
	*file = cfg
	t.Cleanup(func() { *file = old })
	updateIntegration(plugins.Integration{Name: "n"})
	list, _ := readConfig()
	if len(list) != 1 || list[0].Name != "n" {
		t.Fatalf("unexpected list: %v", list)
	}
}

func TestDeleteIntegration(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.yaml")
	old := *file
	*file = cfg
	t.Cleanup(func() { *file = old })
	writeConfig([]plugins.Integration{{Name: "a"}, {Name: "b"}})
	deleteIntegration("a")
	list, _ := readConfig()
	if len(list) != 1 || list[0].Name != "b" {
		t.Fatalf("unexpected list: %v", list)
	}
}

func TestMainMissingArgs(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper", "--", "delete")
	cmd.Env = append(os.Environ(), "GO_WANT_INTEGRATIONS_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(string(out), "delete requires integration name") {
		t.Fatalf("unexpected output: %s", out)
	}

	cmd = exec.Command(os.Args[0], "-test.run=TestMainHelper", "--", "update")
	cmd.Env = append(os.Environ(), "GO_WANT_INTEGRATIONS_HELPER=1")
	out, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(string(out), "update requires plugin name") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestAddIntegrationHelper(t *testing.T) {
	if os.Getenv("GO_WANT_ADDINTEGRATION_HELPER") != "1" {
		return
	}
	cfg := os.Getenv("CFG")
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	file = flag.CommandLine.String("file", cfg, "config file")
	addIntegration(plugins.Integration{Name: "dup"})
	os.Exit(0)
}

func TestAddIntegrationDuplicate(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	old := *file
	*file = cfg
	writeConfig([]plugins.Integration{{Name: "dup"}})
	*file = old

	cmd := exec.Command(os.Args[0], "-test.run=TestAddIntegrationHelper", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_ADDINTEGRATION_HELPER=1", "CFG="+cfg)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(string(out), "already exists") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestAddIntegrationWriteError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sub", "config.yaml")
	cmd := exec.Command(os.Args[0], "-test.run=TestAddIntegrationHelper", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_ADDINTEGRATION_HELPER=1", "CFG="+cfg)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(out) == 0 {
		t.Fatalf("expected error output")
	}
}

func TestAddIntegrationReadError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.yaml")
	os.Mkdir(cfg, 0755)
	cmd := exec.Command(os.Args[0], "-test.run=TestAddIntegrationHelper", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_ADDINTEGRATION_HELPER=1", "CFG="+cfg)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(out) == 0 {
		t.Fatalf("expected error output")
	}
}

func TestUsageOutput(t *testing.T) {
	oldFS := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	buf := &bytes.Buffer{}
	flag.CommandLine.SetOutput(buf)
	file = flag.CommandLine.String("file", "config.yaml", "config file")
	usage()
	if !strings.Contains(buf.String(), "Usage: integrations") {
		t.Fatalf("unexpected usage output: %s", buf.String())
	}
	flag.CommandLine = oldFS
}

func TestMainListCommand(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	old := *file
	*file = cfg
	writeConfig([]plugins.Integration{{Name: "foo"}})
	*file = old

	oldFS := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flag.CommandLine.SetOutput(os.Stdout)
	file = flag.CommandLine.String("file", cfg, "config file")
	defer func() { flag.CommandLine = oldFS }()

	orig := os.Args
	os.Args = []string{"integrations", "list"}
	out := captureOutput(main)
	os.Args = orig

	if !strings.Contains(out, "foo") {
		t.Fatalf("list output incorrect: %s", out)
	}
}

func TestMainAddUpdateDeleteFlow(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")

	run := func(args []string) string {
		oldFS := flag.CommandLine
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		flag.CommandLine.SetOutput(os.Stdout)
		file = flag.CommandLine.String("file", cfg, "config file")
		orig := os.Args
		os.Args = append([]string{"integrations"}, args...)
		out := captureOutput(main)
		os.Args = orig
		flag.CommandLine = oldFS
		return out
	}

	run([]string{"slack", "-name", "s", "-token", "t", "-signing-secret", "ss"})
	out := run([]string{"list"})
	if !strings.Contains(out, "s") {
		t.Fatalf("add/list failed: %s", out)
	}

	run([]string{"update", "slack", "-name", "s", "-token", "t2", "-signing-secret", "ss2"})
	run([]string{"delete", "s"})
	out = run([]string{"list"})
	if strings.TrimSpace(out) != "" {
		t.Fatalf("expected empty list, got %s", out)
	}
}

func TestDeleteIntegrationHelper(t *testing.T) {
	if os.Getenv("GO_WANT_DELETE_HELPER") != "1" {
		return
	}
	cfg := os.Getenv("CFG")
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	file = flag.CommandLine.String("file", cfg, "config file")
	deleteIntegration("foo")
	os.Exit(0)
}

func TestDeleteIntegrationWriteError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sub", "config.yaml")
	cmd := exec.Command(os.Args[0], "-test.run=TestDeleteIntegrationHelper", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_DELETE_HELPER=1", "CFG="+cfg)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(out) == 0 {
		t.Fatalf("expected error output")
	}
}

func TestMainUpdateUnknownPlugin(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper", "--", "update", "nop")
	cmd.Env = append(os.Environ(), "GO_WANT_INTEGRATIONS_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(string(out), "unknown plugin nop") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestMainUpdateBuilderError(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper", "--", "update", "slack", "-token", "t")
	cmd.Env = append(os.Environ(), "GO_WANT_INTEGRATIONS_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(string(out), "-token and -signing-secret are required") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestMainListError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.yaml")
	os.Mkdir(cfg, 0755)
	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper", "--", "-file", cfg, "list")
	cmd.Env = append(os.Environ(), "GO_WANT_INTEGRATIONS_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(out) == 0 {
		t.Fatalf("expected error output")
	}
}

// Helper process for exercising updateIntegration in a separate process.
func TestUpdateIntegrationHelper(t *testing.T) {
	if os.Getenv("GO_WANT_UPDATE_HELPER") != "1" {
		return
	}
	cfg := os.Getenv("CFG")
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	file = flag.CommandLine.String("file", cfg, "config file")
	updateIntegration(plugins.Integration{Name: "foo"})
	os.Exit(0)
}

func TestUpdateIntegrationReadError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.yaml")
	os.Mkdir(cfg, 0755)

	cmd := exec.Command(os.Args[0], "-test.run=TestUpdateIntegrationHelper", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_UPDATE_HELPER=1", "CFG="+cfg)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(out) == 0 {
		t.Fatalf("expected error output")
	}
}

func TestUpdateIntegrationWriteError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sub", "cfg.yaml")

	cmd := exec.Command(os.Args[0], "-test.run=TestUpdateIntegrationHelper", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_UPDATE_HELPER=1", "CFG="+cfg)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(out) == 0 {
		t.Fatalf("expected error output")
	}
}

func TestMainNoArgs(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_INTEGRATIONS_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(string(out), "Usage: integrations") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestMainAddBuilderError(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper", "--", "slack", "-token", "t")
	cmd.Env = append(os.Environ(), "GO_WANT_INTEGRATIONS_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(string(out), "-token and -signing-secret are required") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestListIntegrationHelper(t *testing.T) {
	if os.Getenv("GO_WANT_LIST_HELPER") != "1" {
		return
	}
	cfg := os.Getenv("CFG")
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	file = flag.CommandLine.String("file", cfg, "config file")
	listIntegrations()
	os.Exit(0)
}

func TestListIntegrationsError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.yaml")
	os.Mkdir(cfg, 0755)
	cmd := exec.Command(os.Args[0], "-test.run=TestListIntegrationHelper", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_LIST_HELPER=1", "CFG="+cfg)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(out) == 0 {
		t.Fatalf("expected error output")
	}
}
