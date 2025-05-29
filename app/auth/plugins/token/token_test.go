package token

import (
	"context"
	"net/http"
	"testing"

	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestTokenOutgoingPrefix(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := TokenAuthOut{}
	t.Setenv("TOK", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "Authorization", "prefix": "Bearer "})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(context.Background(), r, cfg)
	if got := r.Header.Get("Authorization"); got != "Bearer secret" {
		t.Fatalf("expected 'Bearer secret', got %s", got)
	}
}

func TestTokenOutgoingMissingSecret(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := TokenAuthOut{}
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:MISS"}, "header": "H"})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(context.Background(), r, cfg)
	if got := r.Header.Get("H"); got != "" {
		t.Fatalf("expected empty header, got %s", got)
	}
}

func TestTokenIncomingPrefix(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer secret"}}}
	p := TokenAuth{}
	t.Setenv("TOK", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "Authorization", "prefix": "Bearer "})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed with prefix")
	}
}

func TestTokenIncomingPrefixMismatch(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer secret"}}}
	p := TokenAuth{}
	t.Setenv("TOK", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "Authorization"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail when prefix not configured")
	}
}

func TestTokenPluginOptionalParams(t *testing.T) {
	in := TokenAuth{}
	out := TokenAuthOut{}
	if got := in.OptionalParams(); len(got) != 1 || got[0] != "prefix" {
		t.Fatalf("unexpected optional params: %v", got)
	}
	if got := out.OptionalParams(); len(got) != 1 || got[0] != "prefix" {
		t.Fatalf("unexpected optional params: %v", got)
	}
}
func TestTokenParseParamsDefaultsAndError(t *testing.T) {
	in := TokenAuth{}
	_, err := in.ParseParams(map[string]interface{}{"secrets": []string{"env:X"}, "header": "H"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.ParseParams(map[string]interface{}{"header": "H"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestTokenAddAuthDefaultPrefix(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := TokenAuthOut{}
	t.Setenv("T", "tok")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:T"}, "header": "H"})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(context.Background(), r, cfg)
	if got := r.Header.Get("H"); got != "tok" {
		t.Fatalf("expected token, got %s", got)
	}
}

func TestTokenAuthenticatePrefixMismatch(t *testing.T) {
	r := &http.Request{Header: http.Header{"H": []string{"pre tok"}}}
	in := TokenAuth{}
	t.Setenv("T", "tok")
	cfg, err := in.ParseParams(map[string]interface{}{"secrets": []string{"env:T"}, "header": "H", "prefix": "pre "})
	if err != nil {
		t.Fatal(err)
	}
	if !in.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected success")
	}
	cfg2, _ := in.ParseParams(map[string]interface{}{"secrets": []string{"env:T"}, "header": "H"})
	if in.Authenticate(context.Background(), r, cfg2) {
		t.Fatal("expected fail without prefix")
	}
}
