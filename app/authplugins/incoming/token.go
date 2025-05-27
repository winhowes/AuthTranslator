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
type tokenParams struct {
	Secrets []string `json:"secrets"`
	Header  string   `json:"header"`
  Prefix  string   `json:"prefix"`
}

type TokenAuth struct{}

func (t *TokenAuth) Name() string { return "token" }
func (t *TokenAuth) RequiredParams() []string { return []string{"token", "header"} }
func (t *TokenAuth) OptionalParams() []string { return []string{"prefix"} }

func (t *TokenAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var p tokenParams
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if len(p.Secrets) == 0 || p.Header == "" {
		return nil, fmt.Errorf("missing secrets or header")
	}
	return &p, nil
}

func (t *TokenAuth) Authenticate(r *http.Request, params interface{}) bool {
	cfg, ok := params.(*tokenParams)
	if !ok {
		return false
	}
	tokenValue := r.Header.Get(cfg.Header)
	tokenValue = strings.TrimPrefix(tokenValue, prefix)
	for _, ref := range cfg.Secrets {
		token, err := secrets.LoadSecret(ref)
		if err == nil && tokenValue == token {
			return true
		}
	}
	return false
}

func init() { authplugins.RegisterIncoming(&TokenAuth{}) }
