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

type stubServer struct{ tls bool }

func (s *stubServer) ListenAndServe() error                    { return nil }
func (s *stubServer) ListenAndServeTLS(cert, key string) error { s.tls = true; return nil }

func TestServeUsesTLS(t *testing.T) {
	srv := &stubServer{}
	if err := serve(srv, "c", "k"); err != nil {
		t.Fatal(err)
	}
	if !srv.tls {
		t.Fatal("expected ListenAndServeTLS to be called")
	}
}

func TestServeMissingTLSArgs(t *testing.T) {
	cases := []struct {
		cert string
		key  string
	}{
		{cert: "c", key: ""},
		{cert: "", key: "k"},
	}
	for i, tc := range cases {
		srv := &stubServer{}
		if err := serve(srv, tc.cert, tc.key); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
		if srv.tls {
			t.Fatalf("case %d: unexpected TLS start", i)
		}
	}
}
