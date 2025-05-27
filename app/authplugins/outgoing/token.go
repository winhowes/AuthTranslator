package outgoing

import (
	"authtransformer/app/secrets"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/winhowes/AuthTransformer/app/authplugins"
)

// TokenAuthOut adds a token header to outbound requests.
type tokenOutParams struct {
	Secrets []string `json:"secrets"`
	Header  string   `json:"header"`
  Prefix  string   `json:"prefix"`
}

type TokenAuthOut struct{}

func (t *TokenAuthOut) Name() string { return "token" }
func (t *TokenAuthOut) RequiredParams() []string { return []string{"token", "header"} }
func (t *TokenAuthOut) OptionalParams() []string { return []string{"prefix"} }

func (t *TokenAuthOut) ParseParams(m map[string]interface{}) (interface{}, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var p tokenOutParams
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if len(p.Secrets) == 0 || p.Header == "" {
		return nil, fmt.Errorf("missing secrets or header")
	}
	return &p, nil
}

func (t *TokenAuthOut) AddAuth(r *http.Request, params interface{}) {
	cfg, ok := params.(*tokenOutParams)
	if !ok || len(cfg.Secrets) == 0 {
		return
	}
	if len(cfg.Secrets) > 1 {
		rand.Seed(time.Now().UnixNano())
	}
	ref := cfg.Secrets[rand.Intn(len(cfg.Secrets))]
	token, err := secrets.LoadSecret(ref)
	if err != nil {
		return
	}
  token = cfg.Prefix + token
	r.Header.Set(cfg.Header, token)
}

func init() { authplugins.RegisterOutgoing(&TokenAuthOut{}) }
