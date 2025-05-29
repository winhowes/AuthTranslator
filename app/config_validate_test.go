package main

import "testing"

func TestValidateConfig(t *testing.T) {
	good := Config{Integrations: []Integration{{Name: "a", Destination: "http://ex"}}}
	if err := validateConfig(&good); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bad := Config{Integrations: []Integration{{Destination: "http://ex"}}}
	if err := validateConfig(&bad); err == nil {
		t.Fatalf("expected error for missing name")
	}
}

func TestValidateConfigBadTimeout(t *testing.T) {
	c := Config{Integrations: []Integration{{Name: "a", Destination: "http://ex", IdleConnTimeout: "not"}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for invalid timeout")
	}
}

func TestValidateConfigBadHandshakeTimeout(t *testing.T) {
	c := Config{Integrations: []Integration{{Name: "a", Destination: "http://ex", TLSHandshakeTimeout: "bad"}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for invalid handshake timeout")
	}
}

func TestValidateConfigBadResponseTimeout(t *testing.T) {
	c := Config{Integrations: []Integration{{Name: "a", Destination: "http://ex", ResponseHeaderTimeout: "nope"}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for invalid response header timeout")
	}
}
