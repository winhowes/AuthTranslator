package basic

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/winhowes/AuthTranslator/app/authplugins"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

// BasicAuthOut sets HTTP Basic credentials on outbound requests.
type outParams struct {
	Secrets []string `json:"secrets"`
	Header  string   `json:"header"`
	Prefix  string   `json:"prefix"`
}

type BasicAuthOut struct{}

func (b *BasicAuthOut) Name() string             { return "basic" }
func (b *BasicAuthOut) RequiredParams() []string { return []string{"secrets"} }
func (b *BasicAuthOut) OptionalParams() []string { return []string{"header", "prefix"} }

func (b *BasicAuthOut) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[outParams](m)
	if err != nil {
		return nil, err
	}
	if len(p.Secrets) == 0 {
		return nil, fmt.Errorf("missing secrets")
	}
	if p.Header == "" {
		p.Header = "Authorization"
	}
	if p.Prefix == "" {
		p.Prefix = "Basic "
	}
	return p, nil
}

func (b *BasicAuthOut) AddAuth(ctx context.Context, r *http.Request, p interface{}) {
	cfg, ok := p.(*outParams)
	if !ok || len(cfg.Secrets) == 0 {
		return
	}
	cred, err := secrets.LoadRandomSecret(ctx, cfg.Secrets)
	if err != nil {
		return
	}
	enc := base64.StdEncoding.EncodeToString([]byte(cred))
	r.Header.Set(cfg.Header, cfg.Prefix+enc)
}

func init() { authplugins.RegisterOutgoing(&BasicAuthOut{}) }
