package main

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestLoadConfigInvalidFile(t *testing.T) {
	_, err := loadConfig("nonexistent.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfigInvalidJSON(t *testing.T) {
	tmp, err := ioutil.TempFile("", "bad*.json")
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
		t.Fatal("expected JSON unmarshal error")
	}
}

func TestLoadConfigUnknownField(t *testing.T) {
	tmp, err := ioutil.TempFile("", "unknown*.json")
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
