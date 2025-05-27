package incoming

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/winhowes/AuthTransformer/app/authplugins"
	"github.com/winhowes/AuthTransformer/app/secrets"
)

// TokenAuth checks that the caller supplied one of the configured tokens.
type params struct {
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
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var p params
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if len(p.Secrets) == 0 || p.Header == "" {
		return nil, fmt.Errorf("missing secrets or header")
	}
	return &p, nil
}

func (t *TokenAuth) Authenticate(r *http.Request, p interface{}) bool {
	cfg, ok := p.(*params)
	if !ok {
		return false
	}
	tokenValue := strings.TrimPrefix(r.Header.Get(cfg.Header), cfg.Prefix)
	for _, ref := range cfg.Secrets {
		token, err := secrets.LoadSecret(ref)
		if err == nil && tokenValue == token {
			return true
		}
	}
	return false
}

func init() { authplugins.RegisterIncoming(&TokenAuth{}) }
