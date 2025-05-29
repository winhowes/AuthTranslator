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

func TestValidateConfigBadName(t *testing.T) {
	c := Config{Integrations: []Integration{{Name: "bad name", Destination: "http://ex"}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for invalid name")
	}
}

func TestValidateConfigDuplicateName(t *testing.T) {
	c := Config{Integrations: []Integration{{Name: "dup", Destination: "http://ex"}, {Name: "DUP", Destination: "http://ex"}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for duplicate name")
	}
}

func TestValidateConfigBadDestination(t *testing.T) {
	c := Config{Integrations: []Integration{{Name: "a", Destination: "example.com"}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for invalid destination")
	}
}

func TestValidateConfigBadIdleConns(t *testing.T) {
	c := Config{Integrations: []Integration{{Name: "a", Destination: "http://ex", MaxIdleConns: -1}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for invalid max idle conns")
	}

	c = Config{Integrations: []Integration{{Name: "b", Destination: "http://ex", MaxIdleConnsPerHost: -2}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for invalid max idle conns per host")
	}
}

func TestValidateConfigBadRateLimitWindow(t *testing.T) {
	c := Config{Integrations: []Integration{{Name: "a", Destination: "http://ex", RateLimitWindow: "bad"}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for invalid rate limit window")
	}

	c = Config{Integrations: []Integration{{Name: "b", Destination: "http://ex", RateLimitWindow: "0"}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for nonpositive rate limit window")
	}
}

func TestValidateConfigNegativeTimeouts(t *testing.T) {
	c := Config{Integrations: []Integration{{Name: "c", Destination: "http://ex", IdleConnTimeout: "-1s"}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for negative idle_conn_timeout")
	}

	c = Config{Integrations: []Integration{{Name: "d", Destination: "http://ex", TLSHandshakeTimeout: "-1s"}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for negative tls_handshake_timeout")
	}

	c = Config{Integrations: []Integration{{Name: "e", Destination: "http://ex", ResponseHeaderTimeout: "-1s"}}}
	if err := validateConfig(&c); err == nil {
		t.Fatalf("expected error for negative response_header_timeout")
	}
}
