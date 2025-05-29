package urlpath

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestURLPathOutgoingAddAuth(t *testing.T) {
	r := &http.Request{URL: &url.URL{Path: "/api"}}
	p := URLPathAuthOut{}
	t.Setenv("URL_SEC1", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:URL_SEC1"}})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(context.Background(), r, cfg)
	if got := r.URL.Path; got != "/api/secret" {
		t.Fatalf("expected '/api/secret', got %s", got)
	}
}

func TestURLPathIncomingAuth(t *testing.T) {
	r := &http.Request{URL: &url.URL{Path: "/api/secret"}}
	p := URLPathAuth{}
	t.Setenv("URL_SEC2", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:URL_SEC2"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
	if got := r.URL.Path; got != "/api" {
		t.Fatalf("expected path '/api', got %s", got)
	}
}

func TestURLPathIncomingAuthFail(t *testing.T) {
	r := &http.Request{URL: &url.URL{Path: "/api/bad"}}
	p := URLPathAuth{}
	t.Setenv("URL_SEC3", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:URL_SEC3"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
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
func TestURLPathTrailingSlash(t *testing.T) {
	r := &http.Request{URL: &url.URL{Path: "/api/"}}
	p := URLPathAuthOut{}
	t.Setenv("URL_SEC4", "s")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:URL_SEC4"}})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(context.Background(), r, cfg)
	if got := r.URL.Path; got != "/api/s" {
		t.Fatalf("expected '/api/s', got %s", got)
	}
	if r.RequestURI != r.URL.RequestURI() {
		t.Fatalf("request URI not updated")
	}
}

func TestURLPathParseParamsError(t *testing.T) {
	in := URLPathAuth{}
	if _, err := in.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error for missing secrets")
	}
}
