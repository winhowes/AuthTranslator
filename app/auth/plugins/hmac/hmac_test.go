package hmacsig

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/winhowes/AuthTranslator/app/secrets"
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

func TestHMACParseParamsInvalidAlgo(t *testing.T) {
	p := HMACSignatureAuth{}
	t.Setenv("SECRET", "k")
	if _, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SECRET"}, "algo": "md5"}); err == nil {
		t.Fatal("expected error for invalid algo")
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

// failPlugin is used to simulate a failing secrets provider.
type failPlugin struct{}

func (failPlugin) Prefix() string { return "fail" }
func (failPlugin) Load(context.Context, string) (string, error) {
	return "", errors.New("fail")
}

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("err") }
func (errReadCloser) Close() error             { return nil }

func TestHMACRequiredParams(t *testing.T) {
	in := HMACSignatureAuth{}
	out := HMACSignature{}
	if got := in.RequiredParams(); len(got) != 1 || got[0] != "secrets" {
		t.Fatalf("unexpected required params: %v", got)
	}
	if got := out.RequiredParams(); len(got) != 1 || got[0] != "secrets" {
		t.Fatalf("unexpected required params: %v", got)
	}
}

func TestHMACParseParamsDefaults(t *testing.T) {
	in := HMACSignatureAuth{}
	out := HMACSignature{}
	t.Setenv("SECRET", "k")
	icfg, err := in.ParseParams(map[string]interface{}{"secrets": []string{"env:SECRET"}})
	if err != nil {
		t.Fatal(err)
	}
	ocfg, err := out.ParseParams(map[string]interface{}{"secrets": []string{"env:SECRET"}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg := icfg.(*inParams); cfg.Header != "X-Signature" || cfg.Algo != "sha256" || cfg.Prefix != "" {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
	if cfg := ocfg.(*outParams); cfg.Header != "X-Signature" || cfg.Algo != "sha256" || cfg.Prefix != "" {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
}

func TestHashFuncVariants(t *testing.T) {
	algos := map[string]int{"sha1": 20, "sha256": 32, "sha512": 64, "": 32}
	for algo, size := range algos {
		f, err := hashFunc(algo)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", algo, err)
		}
		h := f()
		h.Write([]byte("abc"))
		if n := len(h.Sum(nil)); n != size {
			t.Fatalf("unexpected size for %s: %d", algo, n)
		}
		f2, err := hashFuncOut(algo)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", algo, err)
		}
		h2 := f2()
		h2.Write([]byte("abc"))
		if n := len(h2.Sum(nil)); n != size {
			t.Fatalf("unexpected size for %s(out): %d", algo, n)
		}
	}
	if _, err := hashFunc("bad"); err == nil {
		t.Fatal("expected error for bad algo")
	}
	if _, err := hashFuncOut("bad"); err == nil {
		t.Fatal("expected error for bad algo")
	}
}

func TestHMACOutgoingEdgeCases(t *testing.T) {
	secrets.Register(failPlugin{})
	t.Setenv("SECRET", "key")
	p := HMACSignature{}
	// invalid params type
	r := &http.Request{Header: http.Header{}, Body: io.NopCloser(strings.NewReader("body"))}
	p.AddAuth(context.Background(), r, struct{}{})
	if h := r.Header.Get("X-Signature"); h != "" {
		t.Fatalf("expected no header, got %s", h)
	}

	// missing secrets
	r = &http.Request{Header: http.Header{}, Body: io.NopCloser(strings.NewReader("body"))}
	p.AddAuth(context.Background(), r, &outParams{})
	if h := r.Header.Get("X-Signature"); h != "" {
		t.Fatalf("expected no header, got %s", h)
	}

	// secret loading error
	r = &http.Request{Header: http.Header{}, Body: io.NopCloser(strings.NewReader("body"))}
	cfg := &outParams{Secrets: []string{"fail:oops"}}
	p.AddAuth(context.Background(), r, cfg)
	if h := r.Header.Get("X-Signature"); h != "" {
		t.Fatalf("expected no header, got %s", h)
	}

	// body read error
	r = &http.Request{Header: http.Header{}, Body: errReadCloser{}}
	cfg = &outParams{Secrets: []string{"env:SECRET"}}
	p.AddAuth(context.Background(), r, cfg)
	if h := r.Header.Get("X-Signature"); h != "" {
		t.Fatalf("expected no header, got %s", h)
	}

	// unsupported algo
	r = &http.Request{Header: http.Header{}, Body: io.NopCloser(strings.NewReader("body"))}
	cfg = &outParams{Secrets: []string{"env:SECRET"}, Algo: "bad"}
	p.AddAuth(context.Background(), r, cfg)
	if h := r.Header.Get("X-Signature"); h != "" {
		t.Fatalf("expected no header, got %s", h)
	}

	// successful custom header/prefix
	r = &http.Request{Header: http.Header{}, Body: io.NopCloser(strings.NewReader("body"))}
	cfg = &outParams{Secrets: []string{"env:SECRET"}, Header: "Sig", Prefix: "pre:", Algo: "sha512"}
	p.AddAuth(context.Background(), r, cfg)
	mac := hmac.New(sha512.New, []byte("key"))
	mac.Write([]byte("body"))
	expected := "pre:" + hex.EncodeToString(mac.Sum(nil))
	if h := r.Header.Get("Sig"); h != expected {
		t.Fatalf("expected %s, got %s", expected, h)
	}
}

func TestHMACIncomingEdgeCases(t *testing.T) {
	secrets.Register(failPlugin{})
	t.Setenv("SECRET", "key")
	p := HMACSignatureAuth{}
	// invalid params type
	r := &http.Request{Header: http.Header{"X-Signature": []string{"sig"}}, Body: io.NopCloser(strings.NewReader("body"))}
	if p.Authenticate(context.Background(), r, struct{}{}) {
		t.Fatal("expected false for invalid params")
	}

	// body read error
	r = &http.Request{Header: http.Header{"X-Signature": []string{"sig"}}, Body: errReadCloser{}}
	cfg := &inParams{Secrets: []string{"env:SECRET"}}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected false for body read error")
	}

	// missing header
	r = &http.Request{Header: http.Header{}, Body: io.NopCloser(strings.NewReader("body"))}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected false for missing header")
	}

	// unsupported algo
	r = &http.Request{Header: http.Header{"X-Signature": []string{"sig"}}, Body: io.NopCloser(strings.NewReader("body"))}
	cfg = &inParams{Secrets: []string{"env:SECRET"}, Algo: "bad"}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected false for bad algo")
	}

	// secret error then success
	body := "hello"
	mac := hmac.New(sha256.New, []byte("key"))
	mac.Write([]byte(body))
	sig := hex.EncodeToString(mac.Sum(nil))
	r = &http.Request{Header: http.Header{"X-Signature": []string{sig}}, Body: io.NopCloser(strings.NewReader(body))}
	cfg = &inParams{Secrets: []string{"fail:oops", "env:SECRET"}, Header: "X-Signature", Algo: "sha256"}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
}
