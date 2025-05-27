package main

import (
	"net/http"
	"testing"

	"github.com/winhowes/AuthTransformer/app/authplugins/incoming"
	"github.com/winhowes/AuthTransformer/app/authplugins/outgoing"
)

func TestTokenOutgoingPrefix(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := outgoing.TokenAuthOut{}
	params := map[string]string{"token": "secret", "header": "Authorization", "prefix": "Bearer "}
	p.AddAuth(r, params)
	if got := r.Header.Get("Authorization"); got != "Bearer secret" {
		t.Fatalf("expected 'Bearer secret', got %s", got)
	}
}

func TestTokenIncomingPrefix(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer secret"}}}
	p := incoming.TokenAuth{}
	params := map[string]string{"token": "secret", "header": "Authorization", "prefix": "Bearer "}
	if !p.Authenticate(r, params) {
		t.Fatal("expected authentication to succeed with prefix")
	}
}

func TestTokenIncomingPrefixMismatch(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer secret"}}}
	p := incoming.TokenAuth{}
	params := map[string]string{"token": "secret", "header": "Authorization"}
	if p.Authenticate(r, params) {
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
