package token

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"github.com/winhowes/AuthTranslator/app/auth"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

// TokenAuth checks that the caller supplied one of the configured tokens.
type inParams struct {
	Secrets []string `json:"secrets"`
	Header  string   `json:"header"`
	Prefix  string   `json:"prefix"`
}

type TokenAuth struct{}

func (t *TokenAuth) Name() string { return "token" }
func (t *TokenAuth) RequiredParams() []string {
	return []string{"secrets", "header"}
}
func (t *TokenAuth) OptionalParams() []string { return []string{"prefix"} }

func (t *TokenAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[inParams](m)
	if err != nil {
		return nil, err
	}
	if len(p.Secrets) == 0 || p.Header == "" {
		return nil, fmt.Errorf("missing secrets or header")
	}
	return p, nil
}

func (t *TokenAuth) Authenticate(ctx context.Context, r *http.Request, p interface{}) bool {
	cfg, ok := p.(*inParams)
	if !ok {
		return false
	}
	tokenValue := strings.TrimPrefix(r.Header.Get(cfg.Header), cfg.Prefix)
	for _, ref := range cfg.Secrets {
		token, err := secrets.LoadSecret(ctx, ref)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(tokenValue), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

func init() { authplugins.RegisterIncoming(&TokenAuth{}) }
