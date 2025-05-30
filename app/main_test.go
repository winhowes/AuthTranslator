package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
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

func TestHTTP3FlagDefault(t *testing.T) {
	if *enableHTTP3 {
		t.Fatalf("expected default false, got %v", *enableHTTP3)
	}
}

func TestHTTP3FlagSet(t *testing.T) {
	old := *enableHTTP3
	t.Cleanup(func() { flag.Set("enable-http3", strconv.FormatBool(old)) })
	if err := flag.Set("enable-http3", "true"); err != nil {
		t.Fatal(err)
	}
	if !*enableHTTP3 {
		t.Fatal("expected enable-http3 true")
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
	rl := NewRateLimiter(1, time.Hour, "")
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

// parseRedisCommand reads one Redis command from br and returns the command
// name and arguments. It fails the test on protocol errors.
func parseRedisCommand(t *testing.T, br *bufio.Reader) (string, []string) {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if len(line) == 0 || line[0] != '*' {
		t.Fatalf("bad prefix %q", line)
	}
	count, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil {
		t.Fatal(err)
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		if _, err := br.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, strings.TrimSpace(line))
	}
	if len(args) == 0 {
		t.Fatal("no command received")
	}
	cmd := strings.ToUpper(args[0])
	return cmd, args[1:]
}

func TestAllowRedisUnsupportedScheme(t *testing.T) {
	old := *redisAddr
	*redisAddr = "foo://localhost"
	rl := NewRateLimiter(1, time.Second, "")
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
	rl := NewRateLimiter(1, time.Second, "")
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
	rl := NewRateLimiter(1, time.Second, "")
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
	rl := NewRateLimiter(1, time.Second, "")
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

func TestAllowRedisTokenBucket(t *testing.T) {
	rl := NewRateLimiter(2, time.Second, "token_bucket")
	t.Cleanup(rl.Stop)
	srv, cli := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer func() { srv.Close(); close(done) }()
		br := bufio.NewReader(srv)
		if cmd, args := parseRedisCommand(t, br); cmd != "GET" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
			return
		}
		srv.Write([]byte("$-1\r\n"))
		if cmd, args := parseRedisCommand(t, br); cmd != "SET" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
			return
		}
		srv.Write([]byte("+OK\r\n"))
		if cmd, _ := parseRedisCommand(t, br); cmd != "EXPIRE" && cmd != "PEXPIRE" {
			t.Errorf("unexpected command %s", cmd)
			return
		}
		srv.Write([]byte(":1\r\n"))
	}()
	ok, err := rl.allowRedisTokenBucket(cli, "k")
	if err != nil {
		t.Fatalf("allowRedisTokenBucket error: %v", err)
	}
	if !ok {
		t.Fatal("expected token bucket allow")
	}
	<-done
}

func TestAllowRedisTokenBucketReject(t *testing.T) {
	rl := NewRateLimiter(1, time.Hour, "token_bucket")
	t.Cleanup(rl.Stop)
	srv, cli := net.Pipe()
	done := make(chan struct{})
	ts := time.Now().UnixNano()
	go func() {
		defer func() { srv.Close(); close(done) }()
		br := bufio.NewReader(srv)
		if cmd, args := parseRedisCommand(t, br); cmd != "GET" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
			return
		}
		val := fmt.Sprintf("0 %d", ts)
		srv.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(val), val)))
		if cmd, args := parseRedisCommand(t, br); cmd != "SET" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
			return
		}
		srv.Write([]byte("+OK\r\n"))
		if cmd, _ := parseRedisCommand(t, br); cmd != "EXPIRE" && cmd != "PEXPIRE" {
			t.Errorf("unexpected command %s", cmd)
			return
		}
		srv.Write([]byte(":1\r\n"))
	}()
	ok, err := rl.allowRedisTokenBucket(cli, "k")
	if err != nil {
		t.Fatalf("allowRedisTokenBucket error: %v", err)
	}
	if ok {
		t.Fatal("expected token bucket reject")
	}
	<-done
}
func TestAllowRedisLeakyBucketReject(t *testing.T) {
	rl := NewRateLimiter(1, time.Hour, "leaky_bucket")
	t.Cleanup(rl.Stop)
	srv, cli := net.Pipe()
	done := make(chan struct{})
	ts := time.Now().UnixNano()
	go func() {
		defer func() { srv.Close(); close(done) }()
		br := bufio.NewReader(srv)
		if cmd, args := parseRedisCommand(t, br); cmd != "GET" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
			return
		}
		val := fmt.Sprintf("1 %d", ts)
		srv.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(val), val)))
		if cmd, args := parseRedisCommand(t, br); cmd != "SET" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
			return
		}
		srv.Write([]byte("+OK\r\n"))
		if cmd, _ := parseRedisCommand(t, br); cmd != "EXPIRE" && cmd != "PEXPIRE" {
			t.Errorf("unexpected command %s", cmd)
			return
		}
		srv.Write([]byte(":1\r\n"))
	}()
	ok, err := rl.allowRedisLeakyBucket(cli, "k")
	if err != nil {
		t.Fatalf("allowRedisLeakyBucket error: %v", err)
	}
	if ok {
		t.Fatal("expected leaky bucket reject")
	}
	<-done
}

func TestAllowRedisLeakyBucketAllow(t *testing.T) {
	rl := NewRateLimiter(1, time.Hour, "leaky_bucket")
	t.Cleanup(rl.Stop)
	srv, cli := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer func() { srv.Close(); close(done) }()
		br := bufio.NewReader(srv)
		if cmd, args := parseRedisCommand(t, br); cmd != "GET" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
			return
		}
		srv.Write([]byte("$-1\r\n"))
		if cmd, args := parseRedisCommand(t, br); cmd != "SET" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
			return
		}
		srv.Write([]byte("+OK\r\n"))
		if cmd, _ := parseRedisCommand(t, br); cmd != "EXPIRE" && cmd != "PEXPIRE" {
			t.Errorf("unexpected command %s", cmd)
			return
		}
		srv.Write([]byte(":1\r\n"))
	}()
	ok, err := rl.allowRedisLeakyBucket(cli, "k")
	if err != nil {
		t.Fatalf("allowRedisLeakyBucket error: %v", err)
	}
	if !ok {
		t.Fatal("expected leaky bucket allow")
	}
	<-done
}

func TestRetryAfterRedisUnsupportedScheme(t *testing.T) {
	old := *redisAddr
	*redisAddr = "foo://localhost"
	rl := NewRateLimiter(1, time.Second, "")
	t.Cleanup(func() {
		*redisAddr = old
		rl.Stop()
	})
	if _, err := rl.retryAfterRedis("k"); err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestRetryAfterRedisTLSCAError(t *testing.T) {
	oldAddr, oldCA := *redisAddr, *redisCA
	*redisAddr = "rediss://localhost:1"
	*redisCA = "does_not_exist.pem"
	rl := NewRateLimiter(1, time.Second, "")
	t.Cleanup(func() {
		*redisAddr = oldAddr
		*redisCA = oldCA
		rl.Stop()
	})
	if _, err := rl.retryAfterRedis("k"); err == nil {
		t.Fatal("expected error reading CA file")
	}
}

func TestRetryAfterRedisErrorResponse(t *testing.T) {
	old := *redisAddr
	*redisAddr = "dummy"
	rl := NewRateLimiter(1, time.Second, "")
	t.Cleanup(func() {
		*redisAddr = old
		rl.Stop()
	})
	srv, cli := net.Pipe()
	rl.conns <- cli
	done := make(chan struct{})
	go func() {
		defer func() { srv.Close(); close(done) }()
		br := bufio.NewReader(srv)
		if cmd, args := parseRedisCommand(t, br); cmd != "PTTL" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
			return
		}
		srv.Write([]byte("-ERR fail\r\n"))
	}()
	if _, err := rl.retryAfterRedis("k"); err == nil {
		t.Fatal("expected error response")
	}
	<-done
	select {
	case <-rl.conns:
		t.Fatal("connection was returned on error")
	default:
	}
}

func TestRetryAfterRedisTTL(t *testing.T) {
	old := *redisAddr
	*redisAddr = "dummy"
	rl := NewRateLimiter(1, time.Second, "")
	t.Cleanup(func() {
		*redisAddr = old
		rl.Stop()
	})
	srv, cli := net.Pipe()
	rl.conns <- cli
	done := make(chan struct{})
	go func() {
		defer func() { srv.Close(); close(done) }()
		br := bufio.NewReader(srv)
		if cmd, args := parseRedisCommand(t, br); cmd != "PTTL" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
			return
		}
		srv.Write([]byte(":1500\r\n"))
	}()
	d, err := rl.retryAfterRedis("k")
	if err != nil {
		t.Fatalf("retryAfterRedis returned error: %v", err)
	}
	if d != 1500*time.Millisecond {
		t.Fatalf("expected 1500ms, got %v", d)
	}
	<-done
	select {
	case c := <-rl.conns:
		if c != cli {
			t.Fatal("unexpected connection returned")
		}
	default:
		t.Fatal("connection was not returned to pool")
	}
}

func TestRetryAfterRedisNoTTL(t *testing.T) {
	old := *redisAddr
	*redisAddr = "dummy"
	rl := NewRateLimiter(1, time.Second, "")
	t.Cleanup(func() {
		*redisAddr = old
		rl.Stop()
	})

	srv, cli := net.Pipe()
	rl.conns <- cli
	done := make(chan struct{})
	go func() {
		defer func() { srv.Close(); close(done) }()
		br := bufio.NewReader(srv)
		if cmd, args := parseRedisCommand(t, br); cmd != "PTTL" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
			return
		}
		srv.Write([]byte(":-1\r\n"))
	}()

	d, err := rl.retryAfterRedis("k")
	if err != nil {
		t.Fatalf("retryAfterRedis returned error: %v", err)
	}
	if d != 0 {
		t.Fatalf("expected 0 duration, got %v", d)
	}
	<-done
	select {
	case c := <-rl.conns:
		if c != cli {
			t.Fatal("unexpected connection returned")
		}
	default:
		t.Fatal("connection was not returned to pool")
	}
}

func TestRetryAfterRedisNoPool(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	old := *redisAddr
	*redisAddr = ln.Addr().String()
	rl := NewRateLimiter(1, time.Second, "")
	rl.conns = nil
	t.Cleanup(func() {
		*redisAddr = old
		rl.Stop()
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(conn)
		if cmd, args := parseRedisCommand(t, br); cmd != "PTTL" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
		}
		conn.Write([]byte(":0\r\n"))
		conn.Close()
	}()

	d, err := rl.retryAfterRedis("k")
	if err != nil {
		t.Fatalf("retryAfterRedis returned error: %v", err)
	}
	if d != 0 {
		t.Fatalf("expected 0 duration, got %v", d)
	}
	<-done
}

func TestRetryAfterRedisDialError(t *testing.T) {
	oldAddr, oldTimeout := *redisAddr, *redisTimeout
	*redisAddr = "127.0.0.1:1"
	*redisTimeout = 10 * time.Millisecond
	rl := NewRateLimiter(1, time.Second, "")
	t.Cleanup(func() {
		*redisAddr = oldAddr
		*redisTimeout = oldTimeout
		rl.Stop()
	})
	if _, err := rl.retryAfterRedis("k"); err == nil {
		t.Fatal("expected dial error")
	}
}

func TestAllowRedisDialError(t *testing.T) {
	oldAddr, oldTimeout := *redisAddr, *redisTimeout
	*redisAddr = "127.0.0.1:1"
	*redisTimeout = 10 * time.Millisecond
	rl := NewRateLimiter(1, time.Second, "")
	t.Cleanup(func() {
		*redisAddr = oldAddr
		*redisTimeout = oldTimeout
		rl.Stop()
	})
	if _, err := rl.allowRedis("k"); err == nil {
		t.Fatal("expected dial error")
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
	flag.CommandLine.Parse(os.Args[1:])
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

func TestParseLevelValues(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"INFO":    slog.LevelInfo,
		"Warn":    slog.LevelWarn,
		"WARNING": slog.LevelWarn,
		"ERROR":   slog.LevelError,
		"bogus":   slog.LevelInfo,
	}
	for in, want := range cases {
		if got := parseLevel(in); got != want {
			t.Errorf("parseLevel(%q)=%v want %v", in, got, want)
		}
	}
}

func TestRedisTTLArgsEdgecases(t *testing.T) {
	tests := []struct {
		dur      time.Duration
		cmd, val string
	}{
		{1500 * time.Millisecond, "PEXPIRE", "1500"},
		{500 * time.Millisecond, "PEXPIRE", "500"},
		{0, "EXPIRE", "0"},
		{-500 * time.Millisecond, "EXPIRE", "0"},
	}
	for _, tc := range tests {
		cmd, val := redisTTLArgs(tc.dur)
		if cmd != tc.cmd || val != tc.val {
			t.Errorf("redisTTLArgs(%v)=%s %s want %s %s", tc.dur, cmd, val, tc.cmd, tc.val)
		}
	}
}

func TestRedisCmdUnexpectedPrefix(t *testing.T) {
	srv, cli := net.Pipe()
	defer cli.Close()
	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Write([]byte("?bad\r\n"))
		srv.Close()
	}()
	if err := redisCmd(cli, "PING"); err == nil {
		t.Fatal("expected error for unexpected reply prefix")
	}
}

func writeTempFile(t *testing.T, data string) string {
	f, err := os.CreateTemp("", "cfg*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func runMainCmd(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=TestMainHelper", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "GO_WANT_MAIN_HELPER=1")
	return cmd
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestMainRunAndShutdown(t *testing.T) {
	cfg := writeTempFile(t, `{"integrations":[{"name":"test","destination":"http://example.com"}]}`)
	defer os.Remove(cfg)
	al := writeTempFile(t, `[]`)
	defer os.Remove(al)

	cmd := runMainCmd("-config", cfg, "-allowlist", al, "-addr", "127.0.0.1:0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal failed: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("process exit: %v", err)
		}
	case <-time.After(2 * time.Second):
		cmd.Process.Kill()
		t.Fatal("timeout waiting for process exit")
	}
}

func TestMainReloadSignal(t *testing.T) {
	cfg := writeTempFile(t, `{"integrations":[{"name":"test","destination":"http://example.com"}]}`)
	defer os.Remove(cfg)
	al := writeTempFile(t, `[]`)
	defer os.Remove(al)

	cmd := runMainCmd("-config", cfg, "-allowlist", al, "-addr", "127.0.0.1:0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("signal failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("process exited unexpectedly: %v", err)
	}
	cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("process exit: %v", err)
		}
	case <-time.After(2 * time.Second):
		cmd.Process.Kill()
		t.Fatal("timeout waiting for process exit")
	}
}

func TestMainMetricsDisabled(t *testing.T) {
	cfg := writeTempFile(t, `{"integrations":[{"name":"test","destination":"http://example.com"}]}`)
	defer os.Remove(cfg)
	al := writeTempFile(t, `[]`)
	defer os.Remove(al)

	addr := freeAddr(t)
	cmd := runMainCmd("-config", cfg, "-allowlist", al, "-addr", addr, "-enable-metrics=false")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	resp, err := http.Get("http://" + addr + "/_at_internal/metrics")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 when metrics disabled, got %d", resp.StatusCode)
	}
	cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("process exit: %v", err)
		}
	case <-time.After(2 * time.Second):
		cmd.Process.Kill()
		t.Fatal("timeout waiting for process exit")
	}
}

func TestMainMetricsEnabled(t *testing.T) {
	cfg := writeTempFile(t, `{"integrations":[{"name":"test","destination":"http://example.com"}]}`)
	defer os.Remove(cfg)
	al := writeTempFile(t, `[]`)
	defer os.Remove(al)

	addr := freeAddr(t)
	cmd := runMainCmd("-config", cfg, "-allowlist", al, "-addr", addr)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	resp, err := http.Get("http://" + addr + "/_at_internal/metrics")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when metrics enabled, got %d", resp.StatusCode)
	}
	cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("process exit: %v", err)
		}
	case <-time.After(2 * time.Second):
		cmd.Process.Kill()
		t.Fatal("timeout waiting for process exit")
	}
}

func TestMainTLSMissingKey(t *testing.T) {
	cfg := writeTempFile(t, `{"integrations":[{"name":"test","destination":"http://example.com"}]}`)
	defer os.Remove(cfg)
	al := writeTempFile(t, `[]`)
	defer os.Remove(al)
	cert := writeTempFile(t, "dummy")
	defer os.Remove(cert)

	addr := freeAddr(t)
	cmd := runMainCmd("-config", cfg, "-allowlist", al, "-addr", addr, "-tls-cert", cert)
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected process to exit with error")
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() == 0 {
		t.Fatalf("unexpected exit status: %v", err)
	}
}

func TestMainWatchReload(t *testing.T) {
	cfg := writeTempFile(t, `{"integrations":[{"name":"test","destination":"http://example.com"}]}`)
	defer os.Remove(cfg)
	al := writeTempFile(t, `[]`)
	defer os.Remove(al)

	addr := freeAddr(t)
	cmd := runMainCmd("-config", cfg, "-allowlist", al, "-addr", addr, "-watch")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	}()

	time.Sleep(200 * time.Millisecond)

	getReload := func() string {
		resp, err := http.Get("http://" + addr + "/_at_internal/healthz")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		return resp.Header.Get("X-Last-Reload")
	}

	first := getReload()
	if first == "" {
		t.Fatal("missing initial reload header")
	}
	firstTime, err := time.Parse(time.RFC3339, first)
	if err != nil {
		t.Fatalf("invalid reload time: %v", err)
	}

	time.Sleep(time.Second)

	// write same contents with a newline to trigger a write event
	if err := os.WriteFile(cfg, []byte(`{"integrations":[{"name":"test","destination":"http://example.com"}]}`+"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var second string
	start := time.Now()
	for time.Since(start) < 3*time.Second {
		time.Sleep(100 * time.Millisecond)
		second = getReload()
		if second != "" && second != first {
			break
		}
	}
	if second == "" {
		t.Fatal("config change did not trigger reload")
	}
	secondTime, err := time.Parse(time.RFC3339, second)
	if err != nil {
		t.Fatalf("invalid reload time: %v", err)
	}
	if !secondTime.After(firstTime) {
		t.Fatal("config change did not trigger reload")
	}
}

func TestMainMetricsFlagMismatch(t *testing.T) {
	cfg := writeTempFile(t, `{"integrations":[{"name":"test","destination":"http://example.com"}]}`)
	defer os.Remove(cfg)
	al := writeTempFile(t, `[]`)
	defer os.Remove(al)

	addr := freeAddr(t)
	cases := [][]string{
		{"-metrics-user", "admin"},
		{"-metrics-pass", "secret"},
	}
	for i, c := range cases {
		args := append([]string{"-config", cfg, "-allowlist", al, "-addr", addr}, c...)
		cmd := runMainCmd(args...)
		err := cmd.Run()
		if err == nil {
			t.Fatalf("case %d: expected error for metrics flag mismatch", i)
		}
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() == 0 {
			t.Fatalf("case %d: unexpected exit status: %v", i, err)
		}
	}
}
