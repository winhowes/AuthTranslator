package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
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
	if *configFile != "config.yaml" {
		t.Fatalf("expected default config.yaml, got %s", *configFile)
	}
}

func TestConfigFlagSet(t *testing.T) {
	old := *configFile
	t.Cleanup(func() { flag.Set("config", old) })

	if err := flag.Set("config", "custom.yaml"); err != nil {
		t.Fatal(err)
	}
	if *configFile != "custom.yaml" {
		t.Fatalf("expected config custom.yaml, got %s", *configFile)
	}
}

type stubServer struct{ tls bool }

func (s *stubServer) ListenAndServe() error                    { return nil }
func (s *stubServer) ListenAndServeTLS(cert, key string) error { s.tls = true; return nil }

type plainServer struct{ tls, plain bool }

func (s *plainServer) ListenAndServe() error                    { s.plain = true; return nil }
func (s *plainServer) ListenAndServeTLS(cert, key string) error { s.tls = true; return nil }

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

func TestServeNoTLS(t *testing.T) {
	srv := &plainServer{}
	if err := serve(srv, "", ""); err != nil {
		t.Fatal(err)
	}
	if !srv.plain {
		t.Fatal("expected ListenAndServe to be called")
	}
	if srv.tls {
		t.Fatal("unexpected TLS start")
	}
}

func captureUsage() string {
	var buf bytes.Buffer
	old := flag.CommandLine.Output()
	flag.CommandLine.SetOutput(&buf)
	defer flag.CommandLine.SetOutput(old)
	usage()
	return buf.String()
}

func TestUsageOutput(t *testing.T) {
	out := captureUsage()
	if !strings.Contains(out, "Usage: authtranslator") || !strings.Contains(out, "Options:") {
		t.Fatalf("unexpected usage output: %s", out)
	}
}

type errServer struct{}

func (e *errServer) ListenAndServe() error                    { return fmt.Errorf("plain err") }
func (e *errServer) ListenAndServeTLS(cert, key string) error { return fmt.Errorf("tls err") }

func TestServeError(t *testing.T) {
	srv := &errServer{}
	if err := serve(srv, "c", "k"); err == nil || err.Error() != "tls err" {
		t.Fatalf("expected tls error, got %v", err)
	}
	if err := serve(srv, "", ""); err == nil || err.Error() != "plain err" {
		t.Fatalf("expected plain error, got %v", err)
	}
}

func TestRateLimiterStopClosesConnections(t *testing.T) {
	old := *redisAddr
	*redisAddr = "dummy"
	rl := NewRateLimiter(1, time.Hour)
	defer func() { *redisAddr = old }()

	c1, c2 := net.Pipe()
	rl.conns <- c1
	rl.Stop()

	if _, err := c2.Write([]byte("x")); err == nil {
		t.Fatal("expected closed connection")
	}
}
