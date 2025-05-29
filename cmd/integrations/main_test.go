package main

import (
	"encoding/json"
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
