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
	p.StripAuth(r, cfg)
	if h := r.Header.Get("Authorization"); h != "" {
		t.Fatalf("expected header stripped, got %s", h)
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

func TestTokenAddAuthWrongConfigType(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := TokenAuthOut{}
	// pass wrong config type; should not panic or set header
	p.AddAuth(context.Background(), r, struct{}{})
	if val := r.Header.Get("Authorization"); val != "" {
		t.Fatalf("expected no header set, got %s", val)
	}
}

func TestTokenAuthenticateWrongConfigType(t *testing.T) {
	r := &http.Request{Header: http.Header{"H": []string{"tok"}}}
	p := TokenAuth{}
	if p.Authenticate(context.Background(), r, 5) {
		t.Fatal("expected authentication to fail with wrong config")
	}
}

func TestTokenAddAuthMultipleSecrets(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := TokenAuthOut{}
	t.Setenv("TOK1", "a")
	t.Setenv("TOK2", "b")
	cfg, err := p.ParseParams(map[string]interface{}{
		"secrets": []string{"env:TOK1", "env:TOK2"},
		"header":  "H",
	})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(context.Background(), r, cfg)
	got := r.Header.Get("H")
	if got != "a" && got != "b" {
		t.Fatalf("expected one of the secrets, got %s", got)
	}
}

func TestTokenAuthenticateMultipleSecrets(t *testing.T) {
	r := &http.Request{Header: http.Header{"H": []string{"good"}}}
	p := TokenAuth{}
	t.Setenv("BAD", "bad")
	t.Setenv("GOOD", "good")
	cfg, err := p.ParseParams(map[string]interface{}{
		"secrets": []string{"env:BAD", "env:GOOD"},
		"header":  "H",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed with second secret")
	}
}

func TestTokenAuthenticateNoHeader(t *testing.T) {
	p := TokenAuth{}
	t.Setenv("TOK", "tok")
	cfg, _ := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "H"})
	r := &http.Request{Header: http.Header{}}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected failure with missing header")
	}
}

func TestTokenParseParamsMissingHeader(t *testing.T) {
	p := TokenAuth{}
	if _, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:T"}}); err == nil {
		t.Fatal("expected error when header missing")
	}
}

func TestTokenAuthenticateBadToken(t *testing.T) {
	p := TokenAuth{}
	t.Setenv("TOK", "good")
	cfg, _ := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "H"})
	r := &http.Request{Header: http.Header{"H": []string{"bad"}}}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected auth to fail with wrong token")
	}
}

func TestTokenOutgoingParseParamsError(t *testing.T) {
	p := TokenAuthOut{}
	if _, err := p.ParseParams(map[string]interface{}{"header": "H"}); err == nil {
		t.Fatal("expected error for missing secrets")
	}
	if _, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:X"}}); err == nil {
		t.Fatal("expected error for missing header")
	}
}

func TestTokenAuthRequiredParams(t *testing.T) {
	in := TokenAuth{}
	out := TokenAuthOut{}
	if got := in.RequiredParams(); len(got) != 2 || got[0] != "secrets" || got[1] != "header" {
		t.Fatalf("unexpected required params %v", got)
	}
	if got := out.RequiredParams(); len(got) != 2 || got[0] != "secrets" || got[1] != "header" {
		t.Fatalf("unexpected required params %v", got)
	}
}

func TestTokenAddAuthNoSecrets(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := TokenAuthOut{}
	cfg := &outParams{Header: "H"}
	p.AddAuth(context.Background(), r, cfg)
	if val := r.Header.Get("H"); val != "" {
		t.Fatalf("expected no header set, got %s", val)
	}
}

func TestTokenAuthenticateSecretError(t *testing.T) {
	r := &http.Request{Header: http.Header{"H": []string{"tok"}}}
	p := TokenAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:MISSING"}, "header": "H"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail due to secret load error")
	}
}

func TestTokenParseParamsUnknownField(t *testing.T) {
	in := TokenAuth{}
	if _, err := in.ParseParams(map[string]interface{}{
		"secrets": []string{"env:X"},
		"header":  "H",
		"extra":   true,
	}); err == nil {
		t.Fatal("expected error for unknown field")
	}
	out := TokenAuthOut{}
	if _, err := out.ParseParams(map[string]interface{}{
		"secrets": []string{"env:X"},
		"header":  "H",
		"extra":   true,
	}); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestTokenParseParamsTypeMismatch(t *testing.T) {
	in := TokenAuth{}
	if _, err := in.ParseParams(map[string]interface{}{
		"secrets": "bad",
		"header":  "H",
	}); err == nil {
		t.Fatal("expected type mismatch error")
	}
	out := TokenAuthOut{}
	if _, err := out.ParseParams(map[string]interface{}{
		"secrets": "bad",
		"header":  "H",
	}); err == nil {
		t.Fatal("expected type mismatch error")
	}
}
func TestTokenStripAuthInvalidParams(t *testing.T) {
	r := &http.Request{Header: http.Header{"H": []string{"tok"}}}
	p := TokenAuth{}
	p.StripAuth(r, nil)
	if r.Header.Get("H") == "" {
		t.Fatal("header should remain when params nil")
	}
	p.StripAuth(r, struct{}{})
	if r.Header.Get("H") == "" {
		t.Fatal("header should remain when params wrong type")
	}
}
