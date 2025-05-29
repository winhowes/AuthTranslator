package main

import (
	"bufio"
	"net"
	"testing"
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
