package main

import (
	"net/http"
	"testing"

	"github.com/winhowes/AuthTransformer/app/authplugins/incoming"
	"github.com/winhowes/AuthTransformer/app/authplugins/outgoing"
	_ "github.com/winhowes/AuthTransformer/app/secrets/plugins"
)

func TestTokenOutgoingPrefix(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := outgoing.TokenAuthOut{}
	t.Setenv("TOK", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "Authorization", "prefix": "Bearer "})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(r, cfg)
	if got := r.Header.Get("Authorization"); got != "Bearer secret" {
		t.Fatalf("expected 'Bearer secret', got %s", got)
	}
}

func TestTokenIncomingPrefix(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer secret"}}}
	p := incoming.TokenAuth{}
	t.Setenv("TOK", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "Authorization", "prefix": "Bearer "})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(r, cfg) {
		t.Fatal("expected authentication to succeed with prefix")
	}
}

func TestTokenIncomingPrefixMismatch(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer secret"}}}
	p := incoming.TokenAuth{}
	t.Setenv("TOK", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "Authorization"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(r, cfg) {
		t.Fatal("expected authentication to fail when prefix not configured")
	}
}

func TestTokenPluginOptionalParams(t *testing.T) {
	in := incoming.TokenAuth{}
	out := outgoing.TokenAuthOut{}
	if got := in.OptionalParams(); len(got) != 1 || got[0] != "prefix" {
		t.Fatalf("unexpected optional params: %v", got)
	}
	if got := out.OptionalParams(); len(got) != 1 || got[0] != "prefix" {
		t.Fatalf("unexpected optional params: %v", got)
	}
}
