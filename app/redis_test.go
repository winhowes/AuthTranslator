package main

import (
        "bufio"
        "fmt"
        "io"
        "net"
        "strconv"
        "strings"
        "testing"
        "time"
)

func readRESPCommand(t *testing.T, br *bufio.Reader) []string {
        t.Helper()

        line, err := br.ReadString('\n')
        if err != nil {
                t.Fatalf("read command length: %v", err)
        }
        if !strings.HasPrefix(line, "*") {
                t.Fatalf("unexpected command prefix %q", line)
        }
        n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
        if err != nil {
                t.Fatalf("parse command length: %v", err)
        }

        args := make([]string, n)
        for i := 0; i < n; i++ {
                if _, err := br.ReadString('\n'); err != nil {
                        t.Fatalf("read bulk len: %v", err)
                }
                arg, err := br.ReadString('\n')
                if err != nil {
                        t.Fatalf("read bulk data: %v", err)
                }
                args[i] = strings.TrimSpace(arg)
        }
        return args
}

func TestRedisCmdInt(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go func() {
		br := bufio.NewReader(srv)
		// read request
		if _, err := br.ReadBytes('\n'); err != nil {
			return
		}
		if _, err := br.ReadBytes('\n'); err != nil {
			return
		}
		srv.Write([]byte(":5\r\n"))
	}()

	n, err := redisCmdInt(cli, "INCR", "key")
	if err != nil {
		t.Fatalf("redisCmdInt error: %v", err)
	}
	if n != 5 {
		t.Fatalf("redisCmdInt returned %d, want 5", n)
	}
}

func TestRedisCmdIntError(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Write([]byte("-ERR fail\r\n"))
	}()

	_, err := redisCmdInt(cli, "INCR", "key")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRedisCmdIntUnexpected(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Write([]byte("?what\r\n"))
	}()

	if _, err := redisCmdInt(cli, "PING"); err == nil {
		t.Fatal("expected error for unexpected prefix")
	}
}

func TestRedisCmdOK(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Write([]byte("+OK\r\n"))
	}()

	if err := redisCmd(cli, "PING"); err != nil {
		t.Fatalf("redisCmd error: %v", err)
	}
}

func TestRedisCmdError(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Write([]byte("-ERR nope\r\n"))
	}()

	if err := redisCmd(cli, "PING"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRedisCmdUnexpected(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Write([]byte("?bad\r\n"))
	}()

	if err := redisCmd(cli, "PING"); err == nil {
		t.Fatal("expected error for unexpected prefix")
	}
}

type errConn struct{}

func (errConn) Read(b []byte) (int, error)       { return 0, io.EOF }
func (errConn) Write(b []byte) (int, error)      { return 0, fmt.Errorf("write fail") }
func (errConn) Close() error                     { return nil }
func (errConn) LocalAddr() net.Addr              { return nil }
func (errConn) RemoteAddr() net.Addr             { return nil }
func (errConn) SetDeadline(time.Time) error      { return nil }
func (errConn) SetReadDeadline(time.Time) error  { return nil }
func (errConn) SetWriteDeadline(time.Time) error { return nil }

func TestRedisCmdIntWriteError(t *testing.T) {
	if _, err := redisCmdInt(errConn{}, "PING"); err == nil {
		t.Fatal("expected write error")
	}
}

func TestRedisCmdWriteError(t *testing.T) {
	if err := redisCmd(errConn{}, "PING"); err == nil {
		t.Fatal("expected write error")
	}
}

func TestRedisCmdIntReadError(t *testing.T) {
	srv, cli := net.Pipe()
	defer cli.Close()
	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Close()
	}()
	if _, err := redisCmdInt(cli, "INCR", "key"); err == nil {
		t.Fatal("expected read error")
	}
}

func TestRedisCmdReadError(t *testing.T) {
	srv, cli := net.Pipe()
	defer cli.Close()
	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Close()
	}()
	if err := redisCmd(cli, "PING"); err == nil {
		t.Fatal("expected read error")
	}
}

func TestRedisCmdStringOK(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Write([]byte("$3\r\nfoo\r\n"))
	}()

	val, err := redisCmdString(cli, "GET", "key")
	if err != nil {
		t.Fatalf("redisCmdString error: %v", err)
	}
	if val != "foo" {
		t.Fatalf("expected foo, got %q", val)
	}
}

func TestRedisCmdStringNil(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Write([]byte("$-1\r\n"))
	}()

	val, err := redisCmdString(cli, "GET", "key")
	if err != nil {
		t.Fatalf("redisCmdString error: %v", err)
	}
	if val != "" {
		t.Fatalf("expected empty string, got %q", val)
	}
}

func TestRedisCmdStringError(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Write([]byte("-ERR nope\r\n"))
	}()

	if _, err := redisCmdString(cli, "GET", "key"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRedisCmdStringUnexpected(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Write([]byte("?bad\r\n"))
	}()

	if _, err := redisCmdString(cli, "GET", "key"); err == nil {
		t.Fatal("expected error for unexpected prefix")
	}
}

func TestRedisCmdStringWriteError(t *testing.T) {
	if _, err := redisCmdString(errConn{}, "PING"); err == nil {
		t.Fatal("expected write error")
	}
}

func TestRedisCmdStringReadError(t *testing.T) {
	srv, cli := net.Pipe()
	defer cli.Close()
	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Close()
	}()
	if _, err := redisCmdString(cli, "GET", "key"); err == nil {
		t.Fatal("expected read error")
	}
}

func TestRedisCmdStringSimple(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Write([]byte("+PONG\r\n"))
	}()

	val, err := redisCmdString(cli, "PING")
	if err != nil {
		t.Fatalf("redisCmdString error: %v", err)
	}
	if val != "PONG" {
		t.Fatalf("expected PONG, got %q", val)
	}
}

func TestRedisCmdStringInteger(t *testing.T) {
        srv, cli := net.Pipe()
        defer srv.Close()
        defer cli.Close()

	go func() {
		br := bufio.NewReader(srv)
		br.ReadBytes('\n')
		br.ReadBytes('\n')
		srv.Write([]byte(":5\r\n"))
	}()

	val, err := redisCmdString(cli, "INCR", "k")
	if err != nil {
		t.Fatalf("redisCmdString error: %v", err)
	}
	if val != "5" {
		t.Fatalf("expected 5, got %q", val)
        }
}

func TestAllowRedisTokenBucketEmpty(t *testing.T) {
        oldAddr := *redisAddr
        *redisAddr = "redis://example:6379"
        t.Cleanup(func() { *redisAddr = oldAddr })

        rl := NewRateLimiter(1, time.Second, "token_bucket")
        srv, cli := net.Pipe()
        defer srv.Close()
        defer cli.Close()

        now := time.Now().UnixNano()

        go func() {
                br := bufio.NewReader(srv)

                // GET k
                readRESPCommand(t, br)
                payload := fmt.Sprintf("0 %d", now)
                srv.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(payload), payload)))

                // SET k <payload>
                readRESPCommand(t, br)
                srv.Write([]byte("+OK\r\n"))

                // PEXPIRE k <ttl>
                readRESPCommand(t, br)
                srv.Write([]byte(":1\r\n"))
        }()

        allowed, err := rl.allowRedisTokenBucket(cli, "k")
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if allowed {
                t.Fatal("expected request to be rate limited when bucket is empty")
        }
}

func TestAllowRedisLeakyBucketOverLimit(t *testing.T) {
        oldAddr := *redisAddr
        *redisAddr = "redis://example:6379"
        t.Cleanup(func() { *redisAddr = oldAddr })

        rl := NewRateLimiter(1, time.Second, "leaky_bucket")
        now := time.Now().UnixNano()
        srv, cli := net.Pipe()
        defer srv.Close()
        defer cli.Close()

        go func() {
                br := bufio.NewReader(srv)

                // GET k
                readRESPCommand(t, br)
                payload := fmt.Sprintf("2 %d", now)
                srv.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(payload), payload)))

                // SET k <payload>
                readRESPCommand(t, br)
                srv.Write([]byte("+OK\r\n"))

                // PEXPIRE k <ttl>
                readRESPCommand(t, br)
                srv.Write([]byte(":1\r\n"))
        }()

        allowed, err := rl.allowRedisLeakyBucket(cli, "k")
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if allowed {
                t.Fatal("expected request to be rate limited when bucket is over limit")
        }
}

func TestRetryAfterRedisTLSMissingCA(t *testing.T) {
        oldAddr := *redisAddr
        oldCA := *redisCA
        *redisAddr = "rediss://example.com:6379"
        *redisCA = "does-not-exist"
        t.Cleanup(func() {
                *redisAddr = oldAddr
                *redisCA = oldCA
        })

        rl := NewRateLimiter(1, time.Second, "fixed_window")
        if _, err := rl.retryAfterRedis("key"); err == nil {
                t.Fatal("expected error when CA file cannot be read")
        }
}
