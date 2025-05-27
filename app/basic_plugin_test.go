package main

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/winhowes/AuthTransformer/app/authplugins/incoming"
	"github.com/winhowes/AuthTransformer/app/authplugins/outgoing"
	_ "github.com/winhowes/AuthTransformer/app/secrets/plugins"
)

func TestBasicOutgoingAddAuth(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := outgoing.BasicAuthOut{}
	t.Setenv("CREDS", "user:pass")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:CREDS"}})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(r, cfg)
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if got := r.Header.Get("Authorization"); got != expected {
		t.Fatalf("expected %q, got %s", expected, got)
	}
}

func TestBasicIncomingAuth(t *testing.T) {
	cred := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	r := &http.Request{Header: http.Header{"Authorization": []string{"Basic " + cred}}}
	p := incoming.BasicAuth{}
	t.Setenv("CREDS", "user:pass")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:CREDS"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
}

func TestBasicIncomingAuthFail(t *testing.T) {
	cred := base64.StdEncoding.EncodeToString([]byte("user:wrong"))
	r := &http.Request{Header: http.Header{"Authorization": []string{"Basic " + cred}}}
	p := incoming.BasicAuth{}
	t.Setenv("CREDS", "user:pass")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:CREDS"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}

func TestBasicPluginOptionalParams(t *testing.T) {
	in := incoming.BasicAuth{}
	out := outgoing.BasicAuthOut{}
	if got := in.OptionalParams(); len(got) != 2 || got[0] != "header" || got[1] != "prefix" {
		t.Fatalf("unexpected optional params: %v", got)
	}
	if got := out.OptionalParams(); len(got) != 2 || got[0] != "header" || got[1] != "prefix" {
		t.Fatalf("unexpected optional params: %v", got)
	}
}
