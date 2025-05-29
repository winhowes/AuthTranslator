package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

func TestCLIListDeleteUpdate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/integrations", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode([]struct {
				Name string `json:"name"`
			}{{"cli"}})
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPut:
			w.WriteHeader(http.StatusOK)
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// list
	out, err := exec.Command("go", "run", "./cmd/integrations", "-server", srv.URL, "list").CombinedOutput()
	if err != nil {
		t.Fatalf("list failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "cli") {
		t.Fatalf("list output unexpected: %s", out)
	}

	// update
	out, err = exec.Command("go", "run", "./cmd/integrations", "-server", srv.URL, "update", "slack", "-name", "cli", "-token", "t", "-signing-secret", "s").CombinedOutput()
	if err != nil {
		t.Fatalf("update failed: %v\n%s", err, out)
	}

	// delete
	out, err = exec.Command("go", "run", "./cmd/integrations", "-server", srv.URL, "delete", "cli").CombinedOutput()
	if err != nil {
		t.Fatalf("delete failed: %v\n%s", err, out)
	}
}
