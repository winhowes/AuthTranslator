package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
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

// readRedisRequest consumes one Redis request from br.
func readRedisRequest(br *bufio.Reader) error {
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if len(line) < 2 || line[0] != '*' {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil {
		return err
	}
	for i := 0; i < n*2; i++ {
		if _, err := br.ReadString('\n'); err != nil {
			return err
		}
	}
	return nil
}

func TestAllowRedisUnsupportedScheme(t *testing.T) {
	old := *redisAddr
	*redisAddr = "foo://localhost"
	rl := NewRateLimiter(1, time.Second)
	t.Cleanup(func() {
		*redisAddr = old
		rl.Stop()
	})
	if _, err := rl.allowRedis("k"); err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestAllowRedisTLSCAError(t *testing.T) {
	oldAddr, oldCA := *redisAddr, *redisCA
	*redisAddr = "rediss://localhost:1"
	*redisCA = "does_not_exist.pem"
	rl := NewRateLimiter(1, time.Second)
	t.Cleanup(func() {
		*redisAddr = oldAddr
		*redisCA = oldCA
		rl.Stop()
	})
	if _, err := rl.allowRedis("k"); err == nil {
		t.Fatal("expected error reading CA file")
	}
}

func TestAllowRedisErrorResponse(t *testing.T) {
	old := *redisAddr
	*redisAddr = "dummy"
	rl := NewRateLimiter(1, time.Second)
	t.Cleanup(func() {
		*redisAddr = old
		rl.Stop()
	})
	srv, cli := net.Pipe()
	rl.conns <- cli
	go func() {
		br := bufio.NewReader(srv)
		readRedisRequest(br)
		srv.Write([]byte("-ERR fail\r\n"))
		srv.Close()
	}()
	if ok, err := rl.allowRedis("k"); err == nil || ok {
		t.Fatalf("expected error response, got ok=%v err=%v", ok, err)
	}
}

func TestAllowRedisSuccess(t *testing.T) {
	old := *redisAddr
	*redisAddr = "dummy"
	rl := NewRateLimiter(1, time.Second)
	t.Cleanup(func() {
		*redisAddr = old
		rl.Stop()
	})

	srv, cli := net.Pipe()
	rl.conns <- cli
	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		defer srv.Close()
		br := bufio.NewReader(srv)
		// INCR command
		if err := readRedisRequest(br); err != nil {
			errCh <- err
			return
		}
		srv.Write([]byte(":1\r\n"))
		// TTL command
		if err := readRedisRequest(br); err != nil {
			errCh <- err
			return
		}
		srv.Write([]byte(":1\r\n"))
		close(done)
	}()

	ok, err := rl.allowRedis("k")
	if err != nil {
		t.Fatalf("allowRedis returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected allowRedis to return true")
	}
	select {
	case c := <-rl.conns:
		if c != cli {
			t.Fatal("unexpected connection returned")
		}
	default:
		t.Fatal("connection was not returned to pool")
	}
	<-done
	select {
	case err := <-errCh:
		t.Fatalf("goroutine error: %v", err)
	default:
	}
}

// Helper process used for testing main().
func TestMainHelper(t *testing.T) {
	if os.Getenv("GO_WANT_MAIN_HELPER") != "1" {
		return
	}
	for i, a := range os.Args {
		if a == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	main()
	os.Exit(0)
}

func TestMainVersionFlag(t *testing.T) {
	oldArgs := os.Args
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Args = []string{"cmd", "-version"}
	main()
	w.Close()
	os.Stdout = oldStdout
	os.Args = oldArgs
	out, _ := io.ReadAll(r)
	if strings.TrimSpace(string(out)) != version {
		t.Fatalf("expected %q got %q", version, strings.TrimSpace(string(out)))
	}
}

func TestMainReloadFailure(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper", "--", "-config", "no_such_file")
	cmd.Env = append(os.Environ(), "GO_WANT_MAIN_HELPER=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected process to exit with error")
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() == 0 {
		t.Fatalf("unexpected exit status: %v", err)
	}
}
