package urlpath

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/winhowes/AuthTranslator/app/secrets"
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

// failPlugin simulates a failing secrets provider.
type failPlugin struct{}

func (failPlugin) Prefix() string                               { return "fail" }
func (failPlugin) Load(context.Context, string) (string, error) { return "", errors.New("fail") }

func TestURLPathRequiredParams(t *testing.T) {
	in := URLPathAuth{}
	out := URLPathAuthOut{}
	if got := in.RequiredParams(); len(got) != 1 || got[0] != "secrets" {
		t.Fatalf("unexpected required params: %v", got)
	}
	if got := out.RequiredParams(); len(got) != 1 || got[0] != "secrets" {
		t.Fatalf("unexpected required params: %v", got)
	}
}

func TestURLPathOutgoingParseParamsError(t *testing.T) {
	out := URLPathAuthOut{}
	if _, err := out.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error for missing secrets")
	}
}

func TestURLPathOutgoingEdgeCases(t *testing.T) {
	secrets.Register(failPlugin{})
	p := URLPathAuthOut{}
	// invalid params type
	r := &http.Request{URL: &url.URL{Path: "/api"}}
	p.AddAuth(context.Background(), r, struct{}{})
	if r.URL.Path != "/api" {
		t.Fatalf("path changed for invalid params: %s", r.URL.Path)
	}
	// missing secrets
	r = &http.Request{URL: &url.URL{Path: "/api"}}
	p.AddAuth(context.Background(), r, &outParams{})
	if r.URL.Path != "/api" {
		t.Fatalf("path changed for empty secrets: %s", r.URL.Path)
	}
	// secret loading error
	r = &http.Request{URL: &url.URL{Path: "/api"}}
	cfg := &outParams{Secrets: []string{"fail:oops"}}
	p.AddAuth(context.Background(), r, cfg)
	if r.URL.Path != "/api" {
		t.Fatalf("path changed on load failure: %s", r.URL.Path)
	}
}

func TestURLPathIncomingEdgeCases(t *testing.T) {
	secrets.Register(failPlugin{})
	p := URLPathAuth{}
	// invalid params type
	r := &http.Request{URL: &url.URL{Path: "/api/secret"}}
	if p.Authenticate(context.Background(), r, struct{}{}) {
		t.Fatal("expected false for invalid params")
	}
	if r.URL.Path != "/api/secret" {
		t.Fatalf("path changed for invalid params: %s", r.URL.Path)
	}
	// secret loading error
	r = &http.Request{URL: &url.URL{Path: "/api/secret"}}
	cfg := &inParams{Secrets: []string{"fail:oops"}}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected false for secret error")
	}
	if r.URL.Path != "/api/secret" {
		t.Fatalf("path changed on failure: %s", r.URL.Path)
	}
}

func TestURLPathParseParamsUnknownField(t *testing.T) {
	in := URLPathAuth{}
	if _, err := in.ParseParams(map[string]interface{}{
		"secrets": []string{"env:S"},
		"extra":   1,
	}); err == nil {
		t.Fatal("expected error for unknown field")
	}
	out := URLPathAuthOut{}
	if _, err := out.ParseParams(map[string]interface{}{
		"secrets": []string{"env:S"},
		"extra":   1,
	}); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestURLPathParseParamsTypeMismatch(t *testing.T) {
	in := URLPathAuth{}
	if _, err := in.ParseParams(map[string]interface{}{"secrets": "bad"}); err == nil {
		t.Fatal("expected type error")
	}
	out := URLPathAuthOut{}
	if _, err := out.ParseParams(map[string]interface{}{"secrets": "bad"}); err == nil {
		t.Fatal("expected type error")
	}
}
