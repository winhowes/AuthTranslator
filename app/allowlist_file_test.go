package main

import (
	"io/ioutil"
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
