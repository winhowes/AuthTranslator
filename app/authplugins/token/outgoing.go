package token

import (
	"fmt"
	"net/http"

	"github.com/winhowes/AuthTransformer/app/authplugins"
	"github.com/winhowes/AuthTransformer/app/secrets"
)

// TokenAuthOut adds a token header to outbound requests.
type outParams struct {
	Secrets []string `json:"secrets"`
	Header  string   `json:"header"`
	Prefix  string   `json:"prefix"`
}

type TokenAuthOut struct{}

func (t *TokenAuthOut) Name() string { return "token" }
func (t *TokenAuthOut) RequiredParams() []string {
	return []string{"secrets", "header"}
}
func (t *TokenAuthOut) OptionalParams() []string { return []string{"prefix"} }

func (t *TokenAuthOut) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[outParams](m)
	if err != nil {
		return nil, err
	}
	if len(p.Secrets) == 0 || p.Header == "" {
		return nil, fmt.Errorf("missing secrets or header")
	}
	return p, nil
}

func (t *TokenAuthOut) AddAuth(r *http.Request, p interface{}) {
	cfg, ok := p.(*outParams)
	if !ok || len(cfg.Secrets) == 0 {
		return
	}
	token, err := secrets.LoadRandomSecret(cfg.Secrets)
	if err != nil {
		return
	}
	r.Header.Set(cfg.Header, cfg.Prefix+token)
}

func init() { authplugins.RegisterOutgoing(&TokenAuthOut{}) }
