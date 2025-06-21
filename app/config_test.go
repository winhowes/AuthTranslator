package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigInvalidFile(t *testing.T) {
	_, err := loadConfig("nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	tmp, err := os.CreateTemp("", "bad*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString("{invalid}"); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	_, err = loadConfig(tmp.Name())
	if err == nil {
		t.Fatal("expected YAML unmarshal error")
	}
}

func TestLoadConfigUnknownField(t *testing.T) {
	tmp, err := os.CreateTemp("", "unknown*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString("{\"bogus\": 1}"); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	if _, err := loadConfig(tmp.Name()); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestLoadConfigValid(t *testing.T) {
	tmp, err := os.CreateTemp("", "good*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	data := `{"integrations":[{"name":"a","destination":"http://ex"}]}`
	if _, err := tmp.WriteString(data); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	cfg, err := loadConfig(tmp.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Integrations) != 1 || cfg.Integrations[0].Name != "a" || cfg.Integrations[0].Destination != "http://ex" {
		t.Fatalf("unexpected config %+v", cfg)
	}
}

func TestLoadConfigExample(t *testing.T) {
	path := filepath.Join("..", "examples", "config.yaml")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error loading example config: %v", err)
	}
	if len(cfg.Integrations) == 0 {
		t.Fatal("expected at least one integration in example config")
	}
}

func TestLoadConfigURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"integrations":[{"name":"remote","destination":"http://ex"}]}`))
	}))
	defer srv.Close()

	cfg, err := loadConfig(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Integrations) != 1 || cfg.Integrations[0].Name != "remote" {
		t.Fatalf("unexpected config %+v", cfg)
	}
}
