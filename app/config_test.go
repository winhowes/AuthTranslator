package main

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestLoadConfigInvalidFile(t *testing.T) {
	_, err := loadConfig("nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	tmp, err := ioutil.TempFile("", "bad*.yaml")
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
	tmp, err := ioutil.TempFile("", "unknown*.yaml")
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
