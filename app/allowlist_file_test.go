package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestLoadAllowlistsInvalidFile(t *testing.T) {
	_, err := loadAllowlists("nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadAllowlistsInvalidYAML(t *testing.T) {
	tmp, err := ioutil.TempFile("", "bad*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString("{invalid}"); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	_, err = loadAllowlists(tmp.Name())
	if err == nil {
		t.Fatal("expected YAML unmarshal error")
	}
}

func TestLoadAllowlistsUnknownField(t *testing.T) {
	tmp, err := ioutil.TempFile("", "unknown*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString("[{\"bogus\":1}]"); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	if _, err := loadAllowlists(tmp.Name()); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestLoadAllowlistsEmptyFile(t *testing.T) {
	tmp, err := os.CreateTemp("", "empty*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	entries, err := loadAllowlists(tmp.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected zero entries, got %d", len(entries))
	}
}

func TestLoadAllowlistsURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"integration":"test","callers":[]}]`))
	}))
	defer srv.Close()

	entries, err := loadAllowlists(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 || entries[0].Integration != "test" {
		t.Fatalf("unexpected entries %+v", entries)
	}
}
