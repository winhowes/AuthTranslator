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
	cases := []Integration{
		{Name: "a", Destination: "http://ex", TLSHandshakeTimeout: "bogus"},
		{Name: "a", Destination: "http://ex", ResponseHeaderTimeout: "bogus"},
	}
	for _, in := range cases {
		cfg := Config{Integrations: []Integration{in}}
		if err := validateConfig(&cfg); err == nil {
			t.Fatalf("expected error for bad timeout: %+v", in)
		}
	}
}
