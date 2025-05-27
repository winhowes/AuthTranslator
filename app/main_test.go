package main

import (
	"flag"
	"testing"
)

func TestAddrFlagDefault(t *testing.T) {
	if *addr != ":8080" {
		t.Fatalf("expected default :8080, got %s", *addr)
	}
}

func TestAddrFlagSet(t *testing.T) {
	old := *addr
	t.Cleanup(func() { flag.Set("addr", old) })

	if err := flag.Set("addr", "127.0.0.1:9000"); err != nil {
		t.Fatal(err)
	}
	if *addr != "127.0.0.1:9000" {
		t.Fatalf("expected addr 127.0.0.1:9000, got %s", *addr)
	}
}

func TestConfigFlagDefault(t *testing.T) {
	if *configFile != "config.json" {
		t.Fatalf("expected default config.json, got %s", *configFile)
	}
}

func TestConfigFlagSet(t *testing.T) {
	old := *configFile
	t.Cleanup(func() { flag.Set("config", old) })

	if err := flag.Set("config", "custom.json"); err != nil {
		t.Fatal(err)
	}
	if *configFile != "custom.json" {
		t.Fatalf("expected config custom.json, got %s", *configFile)
	}
}
