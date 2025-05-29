package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"reflect"
	"testing"
	"time"

	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/basic"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/google_oidc"
	mtls "github.com/winhowes/AuthTranslator/app/auth/plugins/mtls"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/token"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestAddIntegrationMissingParam(t *testing.T) {
	i := &Integration{
		Name:         "test",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{}}},
	}
	if err := AddIntegration(i); err == nil {
		t.Fatal("expected error for missing params")
	}
}

func TestAddIntegrationValid(t *testing.T) {
	i := &Integration{
		Name:         "testvalid",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "X-Auth"}}},
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})
}

func TestAddIntegrationOptionalParam(t *testing.T) {
	i := &Integration{
		Name:         "testoptional",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "X-Auth", "prefix": "Bearer "}}},
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})
}

func TestAddIntegrationUnknownParam(t *testing.T) {
	i := &Integration{
		Name:         "testunknown",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{"secrets": []string{"x"}, "header": "X-Auth", "bogus": "y"}}},
	}
	if err := AddIntegration(i); err == nil {
		t.Fatal("expected error for unknown param")
	}
}

func TestAddIntegrationInvalidDestination(t *testing.T) {
	i := &Integration{
		Name:         "badurl",
		Destination:  "://bad url",
		InRateLimit:  1,
		OutRateLimit: 1,
	}
	if err := AddIntegration(i); err == nil {
		t.Fatal("expected error for invalid destination")
	}
}

func TestAddIntegrationDuplicateName(t *testing.T) {
	i := &Integration{
		Name:         "testduplicate",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})
	if err := AddIntegration(i); err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestGetIntegrationCaseInsensitive(t *testing.T) {
	i := &Integration{
		Name:         "MiXeD",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})

	if _, ok := GetIntegration("mixed"); !ok {
		t.Fatal("lookup by lowercase failed")
	}
	if _, ok := GetIntegration("MIXED"); !ok {
		t.Fatal("lookup by uppercase failed")
	}
}

func TestUpdateIntegration(t *testing.T) {
	i := &Integration{
		Name:         "update",
		Destination:  "http://a.com",
		InRateLimit:  1,
		OutRateLimit: 1,
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	updated := &Integration{
		Name:         "update",
		Destination:  "http://b.com",
		InRateLimit:  2,
		OutRateLimit: 2,
	}
	if err := UpdateIntegration(updated); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, ok := GetIntegration("update")
	if !ok || got.destinationURL.String() != "http://b.com" {
		t.Fatalf("integration not updated")
	}
	t.Cleanup(func() {
		got.inLimiter.Stop()
		got.outLimiter.Stop()
	})
}

func TestDeleteIntegration(t *testing.T) {
	i := &Integration{
		Name:        "delete",
		Destination: "http://c.com",
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	DeleteIntegration("delete")
	if _, ok := GetIntegration("delete"); ok {
		t.Fatalf("integration not deleted")
	}
}

func TestIntegrationRateLimitWindow(t *testing.T) {
	i := &Integration{
		Name:            "window",
		Destination:     "http://example.com",
		InRateLimit:     1,
		OutRateLimit:    1,
		RateLimitWindow: "10ms",
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})

	if !i.inLimiter.Allow("a") {
		t.Fatal("first call not allowed")
	}
	if i.inLimiter.Allow("a") {
		t.Fatal("limit should be enforced")
	}
	time.Sleep(15 * time.Millisecond)
	if !i.inLimiter.Allow("a") {
		t.Fatal("limit did not reset after window")
	}
}

func TestIntegrationInvalidWindow(t *testing.T) {
	i := &Integration{
		Name:            "badwindow",
		Destination:     "http://example.com",
		InRateLimit:     1,
		OutRateLimit:    1,
		RateLimitWindow: "0",
	}
	if err := AddIntegration(i); err == nil {
		t.Fatal("expected error for non-positive window")
	}
}

func TestIntegrationTransportSettings(t *testing.T) {
	i := &Integration{
		Name:                  "tr",
		Destination:           "http://example.com",
		IdleConnTimeout:       "2s",
		TLSHandshakeTimeout:   "1s",
		ResponseHeaderTimeout: "3s",
		TLSInsecureSkipVerify: true,
		MaxIdleConns:          5,
		MaxIdleConnsPerHost:   3,
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})

	tr, ok := i.proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected http.Transport, got %T", i.proxy.Transport)
	}
	if tr.IdleConnTimeout != 2*time.Second || tr.TLSHandshakeTimeout != 1*time.Second || tr.ResponseHeaderTimeout != 3*time.Second {
		t.Fatalf("transport timeouts not applied")
	}
	if tr.MaxIdleConns != 5 || tr.MaxIdleConnsPerHost != 3 {
		t.Fatalf("idle connection limits not applied")
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("TLS settings not applied")
	}
}

func TestIntegrationDisableKeepAlives(t *testing.T) {
	i := &Integration{
		Name:              "keep",
		Destination:       "http://example.com",
		InRateLimit:       1,
		OutRateLimit:      1,
		DisableKeepAlives: true,
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})

	tr, ok := i.proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected http.Transport, got %T", i.proxy.Transport)
	}
	if !tr.DisableKeepAlives {
		t.Fatalf("DisableKeepAlives not applied")
	}
}

func TestIntegrationPluginTransport(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	t.Setenv("CERT", string(certPEM))
	t.Setenv("KEY", string(keyPEM))

	p := mtls.MTLSAuthOut{}
	cfg, err := p.ParseParams(map[string]interface{}{"cert": "env:CERT", "key": "env:KEY"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	baseTr := p.Transport(cfg)
	if baseTr == nil {
		t.Fatal("missing base transport")
	}

	i := &Integration{
		Name:              "plug",
		Destination:       "http://example.com",
		InRateLimit:       1,
		OutRateLimit:      1,
		IdleConnTimeout:   "1s",
		DisableKeepAlives: true,
		OutgoingAuth: []AuthPluginConfig{{
			Type:   "mtls",
			Params: map[string]interface{}{"cert": "env:CERT", "key": "env:KEY"},
		}},
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})

	tr, ok := i.proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected http.Transport, got %T", i.proxy.Transport)
	}
	if tr == baseTr {
		t.Fatalf("transport not cloned")
	}
	if tr.IdleConnTimeout != time.Second || !tr.DisableKeepAlives {
		t.Fatalf("integration settings not applied")
	}
	if baseTr.IdleConnTimeout != 0 {
		t.Fatalf("base transport mutated")
	}
	if tr.TLSClientConfig == nil || len(tr.TLSClientConfig.Certificates) == 0 {
		t.Fatalf("TLS certificates missing")
	}
	if !reflect.DeepEqual(tr.TLSClientConfig.Certificates, baseTr.TLSClientConfig.Certificates) {
		t.Fatalf("certificates not preserved")
	}
}
