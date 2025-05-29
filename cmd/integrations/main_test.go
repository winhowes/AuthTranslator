package main

import (
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
	// Recreate flag set and server flag so we can parse arguments.
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	server = flag.CommandLine.String("server", *server, "integration endpoint")
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

func TestMainServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper", "--", "-server", srv.URL+"/integrations", "update", "slack", "-token", "t", "-signing-secret", "s")
	cmd.Env = append(os.Environ(), "GO_WANT_INTEGRATIONS_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(string(out), "server error") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestMainListInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("notjson"))
	}))
	defer srv.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper", "--", "-server", srv.URL+"/integrations", "list")
	cmd.Env = append(os.Environ(), "GO_WANT_INTEGRATIONS_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(string(out), "invalid character") {
		t.Fatalf("unexpected output: %s", out)
	}
}
