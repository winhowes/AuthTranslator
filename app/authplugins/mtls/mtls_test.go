package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"testing"

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
	if !p.Authenticate(r, cfg) {
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
	if p.Authenticate(r, cfg) {
		t.Fatal("expected failure without TLS")
	}
}

func TestMTLSOutgoingParse(t *testing.T) {
	p := MTLSAuthOut{}
	cfg, err := p.ParseParams(map[string]interface{}{"cert": "env:CERT", "key": "env:KEY"})
	if err != nil {
		t.Fatal(err)
	}
	params, ok := cfg.(*outParams)
	if !ok || params.Cert != "env:CERT" || params.Key != "env:KEY" {
		t.Fatalf("unexpected config %+v", cfg)
	}
	r := &http.Request{Header: http.Header{}}
	p.AddAuth(r, cfg)
	if len(r.Header) != 0 {
		t.Fatalf("expected no headers set, got %v", r.Header)
	}
}
