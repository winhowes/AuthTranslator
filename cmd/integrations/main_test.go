package main

import (
	"io"
	"os"
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
