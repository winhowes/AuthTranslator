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
