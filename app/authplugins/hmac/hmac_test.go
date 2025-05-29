package hmacsig

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"

	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestHMACOutgoingAddAuth(t *testing.T) {
	r := &http.Request{Header: http.Header{}, Body: io.NopCloser(strings.NewReader("hello"))}
	p := HMACSignature{}
	t.Setenv("SECRET", "key")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SECRET"}})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(context.Background(), r, cfg)
	mac := hmac.New(sha256.New, []byte("key"))
	mac.Write([]byte("hello"))
	expected := hex.EncodeToString(mac.Sum(nil))
	if got := r.Header.Get("X-Signature"); got != expected {
		t.Fatalf("expected %s, got %s", expected, got)
	}
}

func TestHMACIncomingAuth(t *testing.T) {
	body := "hello"
	mac := hmac.New(sha256.New, []byte("key"))
	mac.Write([]byte(body))
	sig := hex.EncodeToString(mac.Sum(nil))
	r := &http.Request{Header: http.Header{"X-Signature": []string{sig}}, Body: io.NopCloser(strings.NewReader(body))}
	p := HMACSignatureAuth{}
	t.Setenv("SECRET", "key")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SECRET"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
}

func TestHMACIncomingAuthFail(t *testing.T) {
	body := "hello"
	mac := hmac.New(sha256.New, []byte("bad"))
	mac.Write([]byte(body))
	sig := hex.EncodeToString(mac.Sum(nil))
	r := &http.Request{Header: http.Header{"X-Signature": []string{sig}}, Body: io.NopCloser(strings.NewReader(body))}
	p := HMACSignatureAuth{}
	t.Setenv("SECRET", "key")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SECRET"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}

func TestHMACPluginOptionalParams(t *testing.T) {
	in := HMACSignatureAuth{}
	out := HMACSignature{}
	if got := in.OptionalParams(); len(got) != 3 || got[0] != "header" {
		t.Fatalf("unexpected optional params: %v", got)
	}
	if got := out.OptionalParams(); len(got) != 3 || got[0] != "header" {
		t.Fatalf("unexpected optional params: %v", got)
	}
}
