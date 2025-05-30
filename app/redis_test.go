package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

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
