package token

import (
	"context"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
	"net/http"
	"testing"
)

func TestTokenAuthenticateRequiresPrefix(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"secret"}}}
	p := TokenAuth{}
	t.Setenv("TOK", "secret")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "Authorization", "prefix": "Bearer "})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail without prefix")
	}
}
