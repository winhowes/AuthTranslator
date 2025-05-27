package urlpath

import (
	"net/http"
	"net/url"
	"testing"

	_ "github.com/winhowes/AuthTransformer/app/secrets/plugins"
)

func TestURLPathOutgoingAddAuth(t *testing.T) {
	r := &http.Request{URL: &url.URL{Path: "/api"}}
	p := URLPathAuthOut{}
	t.Setenv("SEC", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(r, cfg)
	if got := r.URL.Path; got != "/api/secret" {
		t.Fatalf("expected '/api/secret', got %s", got)
	}
}

func TestURLPathIncomingAuth(t *testing.T) {
	r := &http.Request{URL: &url.URL{Path: "/api/secret"}}
	p := URLPathAuth{}
	t.Setenv("SEC", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
	if got := r.URL.Path; got != "/api" {
		t.Fatalf("expected path '/api', got %s", got)
	}
}

func TestURLPathIncomingAuthFail(t *testing.T) {
	r := &http.Request{URL: &url.URL{Path: "/api/bad"}}
	p := URLPathAuth{}
	t.Setenv("SEC", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}

func TestURLPathPluginOptionalParams(t *testing.T) {
	in := URLPathAuth{}
	out := URLPathAuthOut{}
	if got := in.OptionalParams(); got != nil && len(got) != 0 {
		t.Fatalf("unexpected optional params: %v", got)
	}
	if got := out.OptionalParams(); got != nil && len(got) != 0 {
		t.Fatalf("unexpected optional params: %v", got)
	}
}
