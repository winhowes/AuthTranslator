package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func readCommand(t *testing.T, br *bufio.Reader) string {
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
	line, err = br.ReadString('\n') // $len
	if err != nil {
		t.Fatal(err)
	}
	line, err = br.ReadString('\n') // command
	if err != nil {
		t.Fatal(err)
	}
	cmd := strings.ToUpper(strings.TrimSpace(line))
	for i := 1; i < count; i++ {
		if _, err := br.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		if _, err := br.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
	}
	return cmd
}

func TestRateLimiterRedisAuth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		if cmd := readCommand(t, br); cmd != "AUTH" {
			t.Errorf("cmd %s, want AUTH", cmd)
			return
		}
		c.Write([]byte("+OK\r\n"))
		if cmd := readCommand(t, br); cmd != "INCR" {
			t.Errorf("cmd %s, want INCR", cmd)
		}
		c.Write([]byte(":1\r\n"))
		if cmd := readCommand(t, br); cmd != "EXPIRE" {
			t.Errorf("cmd %s, want EXPIRE", cmd)
		}
		c.Write([]byte(":1\r\n"))
	}()
	oldAddr := *redisAddr
	oldTimeout := *redisTimeout
	*redisAddr = "redis://:pw@" + ln.Addr().String()
	*redisTimeout = time.Second
	rl := NewRateLimiter(1, time.Second)
	defer func() {
		rl.Stop()
		*redisAddr = oldAddr
		*redisTimeout = oldTimeout
	}()
	if !rl.Allow("k") {
		t.Fatal("allow failed")
	}
	<-done
}

func TestRateLimiterRedisTLSAuth(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "srv"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		if cmd := readCommand(t, br); cmd != "AUTH" {
			t.Errorf("cmd %s, want AUTH", cmd)
			return
		}
		c.Write([]byte("+OK\r\n"))
		if cmd := readCommand(t, br); cmd != "INCR" {
			t.Errorf("cmd %s, want INCR", cmd)
		}
		c.Write([]byte(":1\r\n"))
		if cmd := readCommand(t, br); cmd != "EXPIRE" {
			t.Errorf("cmd %s, want EXPIRE", cmd)
		}
		c.Write([]byte(":1\r\n"))
	}()
	oldAddr := *redisAddr
	oldTimeout := *redisTimeout
	*redisAddr = "rediss://:pw@" + ln.Addr().String()
	*redisTimeout = time.Second
	rl := NewRateLimiter(1, time.Second)
	defer func() {
		rl.Stop()
		*redisAddr = oldAddr
		*redisTimeout = oldTimeout
	}()
	if !rl.Allow("k") {
		t.Fatal("allow failed")
	}
	<-done
}

func TestRateLimiterRedisTLSVerify(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "srv"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)})
	cert, _ := tls.X509KeyPair(srvCertPEM, srvKeyPEM)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		if cmd := readCommand(t, br); cmd != "AUTH" {
			t.Errorf("cmd %s, want AUTH", cmd)
			return
		}
		c.Write([]byte("+OK\r\n"))
		if cmd := readCommand(t, br); cmd != "INCR" {
			t.Errorf("cmd %s, want INCR", cmd)
		}
		c.Write([]byte(":1\r\n"))
		if cmd := readCommand(t, br); cmd != "EXPIRE" {
			t.Errorf("cmd %s, want EXPIRE", cmd)
		}
		c.Write([]byte(":1\r\n"))
	}()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFile, caPEM, 0600)
	oldAddr := *redisAddr
	oldTimeout := *redisTimeout
	oldCA := *redisCA
	*redisAddr = "rediss://:pw@" + ln.Addr().String()
	*redisTimeout = time.Second
	*redisCA = caFile
	rl := NewRateLimiter(1, time.Second)
	defer func() {
		rl.Stop()
		*redisAddr = oldAddr
		*redisTimeout = oldTimeout
		*redisCA = oldCA
	}()
	if !rl.Allow("k") {
		t.Fatal("allow failed")
	}
	<-done
}
