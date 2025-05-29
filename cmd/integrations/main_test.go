package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/winhowes/AuthTranslator/cmd/integrations/plugins"
)

type exitCode struct{ code int }

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

// expectExit runs f and expects it to call exit with code.
func expectExit(t *testing.T, code int, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			if ec, ok := r.(exitCode); ok {
				if ec.code != code {
					t.Fatalf("expected exit %d, got %d", code, ec.code)
				}
			} else {
				panic(r)
			}
		} else {
			t.Fatalf("expected exit %d", code)
		}
	}()
	f()
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

func TestMainCreateCommand(t *testing.T) {
	var method string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		w.WriteHeader(http.StatusCreated)
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
	os.Args = []string{"integrations", "-server", srv.URL, "slack", "-token", "t", "-signing-secret", "s"}
	defer func() { os.Args = origArgs }()

	out := captureOutput(main)
	if method != http.MethodPost {
		t.Fatalf("expected POST, got %s", method)
	}
	if !strings.Contains(out, "integration added") {
		t.Fatalf("create output unexpected: %s", out)
	}
}

func TestMainNoArgs(t *testing.T) {
	oldFS := flag.CommandLine
	oldExit := exit
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	exit = func(c int) { panic(exitCode{c}) }
	defer func() {
		flag.CommandLine = oldFS
		exit = oldExit
	}()

	os.Args = []string{"integrations"}
	expectExit(t, 1, main)
}

func TestMainUpdateMissingPlugin(t *testing.T) {
	oldFS := flag.CommandLine
	oldServer := server
	oldExit := exit
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	server = flag.CommandLine.String("server", "http://example", "integration endpoint")
	exit = func(c int) { panic(exitCode{c}) }
	defer func() {
		flag.CommandLine = oldFS
		server = oldServer
		exit = oldExit
	}()

	os.Args = []string{"integrations", "update"}
	expectExit(t, 1, main)
}

func TestMainUpdateUnknownPlugin(t *testing.T) {
	oldFS := flag.CommandLine
	oldServer := server
	oldExit := exit
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	server = flag.CommandLine.String("server", "http://example", "integration endpoint")
	exit = func(c int) { panic(exitCode{c}) }
	defer func() {
		flag.CommandLine = oldFS
		server = oldServer
		exit = oldExit
	}()

	os.Args = []string{"integrations", "update", "bogus"}
	expectExit(t, 1, main)
}

func TestMainUpdateBuilderError(t *testing.T) {
	plugins.Register("failb", func(args []string) (plugins.Integration, error) {
		return plugins.Integration{}, fmt.Errorf("bad")
	})

	oldFS := flag.CommandLine
	oldServer := server
	oldExit := exit
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	server = flag.CommandLine.String("server", "http://example", "integration endpoint")
	exit = func(c int) { panic(exitCode{c}) }
	defer func() {
		flag.CommandLine = oldFS
		server = oldServer
		exit = oldExit
	}()

	os.Args = []string{"integrations", "update", "failb"}
	expectExit(t, 1, main)
}

// Helper process for exercising main() in a separate process.
func TestMainUnknownPlugin(t *testing.T) {
	oldFS := flag.CommandLine
	oldServer := server
	oldExit := exit
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	server = flag.CommandLine.String("server", "http://example.com", "integration endpoint")
	exit = func(c int) { panic(exitCode{c}) }
	defer func() {
		flag.CommandLine = oldFS
		server = oldServer
		exit = oldExit
	}()

	os.Args = []string{"integrations", "unknown"}
	expectExit(t, 1, main)
}

func TestMainServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	oldFS := flag.CommandLine
	oldServer := server
	oldExit := exit
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	server = flag.CommandLine.String("server", srv.URL+"/integrations", "integration endpoint")
	exit = func(c int) { panic(exitCode{c}) }
	defer func() {
		flag.CommandLine = oldFS
		server = oldServer
		exit = oldExit
	}()

	os.Args = []string{"integrations", "update", "slack", "-token", "t", "-signing-secret", "s"}
	expectExit(t, 1, main)
}

func TestMainListInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("notjson"))
	}))
	defer srv.Close()

	oldFS := flag.CommandLine
	oldServer := server
	oldExit := exit
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	server = flag.CommandLine.String("server", srv.URL+"/integrations", "integration endpoint")
	exit = func(c int) { panic(exitCode{c}) }
	defer func() {
		flag.CommandLine = oldFS
		server = oldServer
		exit = oldExit
	}()

	os.Args = []string{"integrations", "list"}
	expectExit(t, 1, main)
}

func TestSendIntegrationWithMethodError(t *testing.T) {
	integ := plugins.Integration{Name: "bad"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	oldServer := *server
	oldExit := exit
	*server = srv.URL
	exit = func(c int) { panic(exitCode{c}) }
	defer func() {
		*server = oldServer
		exit = oldExit
	}()

	expectExit(t, 1, func() { sendIntegrationWithMethod(http.MethodPost, integ) })
}

func TestDeleteIntegrationError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("fail"))
	}))
	defer srv.Close()

	oldServer := *server
	oldExit := exit
	*server = srv.URL
	exit = func(c int) { panic(exitCode{c}) }
	defer func() {
		*server = oldServer
		exit = oldExit
	}()

	expectExit(t, 1, func() { deleteIntegration("x") })
}

func TestListIntegrationsServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	oldServer := *server
	oldExit := exit
	*server = srv.URL
	exit = func(c int) { panic(exitCode{c}) }
	defer func() {
		*server = oldServer
		exit = oldExit
	}()

	expectExit(t, 1, listIntegrations)
}

func TestListIntegrationsDecodeErrorDirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("notjson"))
	}))
	defer srv.Close()

	oldServer := *server
	oldExit := exit
	*server = srv.URL
	exit = func(c int) { panic(exitCode{c}) }
	defer func() {
		*server = oldServer
		exit = oldExit
	}()

	expectExit(t, 1, listIntegrations)
}
