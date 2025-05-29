package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/winhowes/AuthTranslator/cmd/integrations/plugins"
)

// captureOutput captures stdout from f and returns it as a string.
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

func TestSendIntegrationWithMethodPost(t *testing.T) {
	integ := plugins.Integration{Name: "foo"}

	var reqMethod string
	var reqBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqMethod = r.Method
		reqBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	old := *server
	*server = srv.URL
	t.Cleanup(func() { *server = old })

	out := captureOutput(func() { sendIntegrationWithMethod(http.MethodPost, integ) })

	if reqMethod != http.MethodPost {
		t.Fatalf("expected POST request, got %s", reqMethod)
	}

	var got plugins.Integration
	if err := json.Unmarshal(reqBody, &got); err != nil {
		t.Fatalf("invalid body: %v", err)
	}
	if got.Name != integ.Name {
		t.Fatalf("expected integration %s, got %s", integ.Name, got.Name)
	}
	if !strings.Contains(out, "integration added") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestSendIntegrationWithMethodPut(t *testing.T) {
	integ := plugins.Integration{Name: "bar"}

	var reqMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := *server
	*server = srv.URL
	t.Cleanup(func() { *server = old })

	out := captureOutput(func() { sendIntegrationWithMethod(http.MethodPut, integ) })

	if reqMethod != http.MethodPut {
		t.Fatalf("expected PUT request, got %s", reqMethod)
	}
	if !strings.Contains(out, "integration updated") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestDeleteIntegration(t *testing.T) {
	var reqMethod, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqMethod = r.Method
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	old := *server
	*server = srv.URL
	t.Cleanup(func() { *server = old })

	out := captureOutput(func() { deleteIntegration("baz") })

	if reqMethod != http.MethodDelete {
		t.Fatalf("expected DELETE request, got %s", reqMethod)
	}

	var payload struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("invalid body: %v", err)
	}
	if payload.Name != "baz" {
		t.Fatalf("expected name baz, got %s", payload.Name)
	}
	if !strings.Contains(out, "integration deleted") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestListIntegrations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET request, got %s", r.Method)
		}
		list := []struct {
			Name string `json:"name"`
		}{{"i1"}, {"i2"}}
		json.NewEncoder(w).Encode(list)
	}))
	defer srv.Close()

	old := *server
	*server = srv.URL
	t.Cleanup(func() { *server = old })

	out := captureOutput(listIntegrations)

	if !strings.Contains(out, "i1") || !strings.Contains(out, "i2") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestUsageOutput(t *testing.T) {
	oldFS := flag.CommandLine
	oldServer := server
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	buf := &bytes.Buffer{}
	flag.CommandLine.SetOutput(buf)
	server = flag.CommandLine.String("server", *oldServer, "integration endpoint")
	t.Cleanup(func() {
		flag.CommandLine = oldFS
		server = oldServer
	})

	usage()
	out := buf.String()
	if !strings.Contains(out, "Usage: integrations") {
		t.Fatalf("usage output unexpected: %s", out)
	}
}

func TestMainListCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		json.NewEncoder(w).Encode([]struct {
			Name string `json:"name"`
		}{{"m1"}})
	}))
	defer srv.Close()

	oldFS := flag.CommandLine
	oldServer := server
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	server = flag.CommandLine.String("server", srv.URL, "integration endpoint")
	t.Cleanup(func() {
		flag.CommandLine = oldFS
		server = oldServer
	})

	origArgs := os.Args
	os.Args = []string{"integrations", "-server", srv.URL, "list"}
	defer func() { os.Args = origArgs }()

	out := captureOutput(main)
	if !strings.Contains(out, "m1") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestMainUpdateDeleteCommands(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	oldFS := flag.CommandLine
	oldServer := server
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	server = flag.CommandLine.String("server", srv.URL, "integration endpoint")
	t.Cleanup(func() {
		flag.CommandLine = oldFS
		server = oldServer
	})

	origArgs := os.Args
	os.Args = []string{"integrations", "-server", srv.URL, "update", "slack", "-token", "t", "-signing-secret", "s"}
	out := captureOutput(main)
	if !strings.Contains(out, "integration updated") {
		t.Fatalf("update output unexpected: %s", out)
	}

	os.Args = []string{"integrations", "-server", srv.URL, "delete", "slack"}
	out = captureOutput(main)
	if !strings.Contains(out, "integration deleted") {
		t.Fatalf("delete output unexpected: %s", out)
	}
	defer func() { os.Args = origArgs }()

	if len(methods) != 2 || methods[0] != http.MethodPut || methods[1] != http.MethodDelete {
		t.Fatalf("requests not issued as expected: %v", methods)
	}
}
