package mtls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestMTLSAuth(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "client"}}
	r := &http.Request{TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}, PeerCertificates: []*x509.Certificate{cert}}}
	p := MTLSAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"subjects": []string{"client"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
	id, ok := p.Identify(r, cfg)
	if !ok || id != "client" {
		t.Fatalf("unexpected id %s", id)
	}
}

func TestMTLSAuthFail(t *testing.T) {
	r := &http.Request{}
	p := MTLSAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"subjects": []string{"client"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected failure without TLS")
	}
}

func TestMTLSOutgoingParse(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	p := MTLSAuthOut{}
	t.Setenv("CERT", string(certPEM))
	t.Setenv("KEY", string(keyPEM))
	cfg, err := p.ParseParams(map[string]interface{}{"cert": "env:CERT", "key": "env:KEY"})
	if err != nil {
		t.Fatal(err)
	}
	params, ok := cfg.(*outParams)
	if !ok || params.Cert != "env:CERT" || params.Key != "env:KEY" {
		t.Fatalf("unexpected config %+v", cfg)
	}
	r := &http.Request{Header: http.Header{}}
	p.AddAuth(context.Background(), r, cfg)
	if got := r.Header.Get("X-TLS-Client-CN"); got != "client" {
		t.Fatalf("expected client CN header, got %s", got)
	}
}

func TestMTLSOutgoingAddAuth(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	p := MTLSAuthOut{}
	t.Setenv("CERT", string(certPEM))
	t.Setenv("KEY", string(keyPEM))
	cfg, err := p.ParseParams(map[string]interface{}{"cert": "env:CERT", "key": "env:KEY"})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{}}
	p.AddAuth(context.Background(), r, cfg)
	if got := r.Header.Get("X-TLS-Client-CN"); got != "client" {
		t.Fatalf("expected client CN header, got %s", got)
	}
}

func TestMTLSOutgoingTransport(t *testing.T) {
	// Generate CA, server, and client certificates.
	caKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

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
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)})
	srvTLS, _ := tls.X509KeyPair(srvCertPEM, srvKeyPEM)

	cliKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "client"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	cliDER, _ := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, &cliKey.PublicKey, caKey)
	cliCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliDER})
	cliKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cliKey)})

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	hit := false
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		if r.TLS.PeerCertificates[0].Subject.CommonName != "client" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{srvTLS}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	ts.StartTLS()
	defer ts.Close()

	t.Setenv("CCERT", string(cliCertPEM))
	t.Setenv("CKEY", string(cliKeyPEM))

	p := MTLSAuthOut{}
	cfgIntf, err := p.ParseParams(map[string]interface{}{"cert": "env:CCERT", "key": "env:CKEY"})
	if err != nil {
		t.Fatal(err)
	}
	tr := p.Transport(cfgIntf)
	if tr == nil {
		t.Fatal("missing transport")
	}
	tr.TLSClientConfig.RootCAs = pool

	c := http.Client{Transport: tr}
	resp, err := c.Get(ts.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if !hit {
		t.Fatal("server not hit")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
