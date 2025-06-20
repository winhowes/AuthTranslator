package jwt

import (
	"context"
	"fmt"
	"net/http"

	"github.com/winhowes/AuthTranslator/app/auth"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

// outParams configures JWT forwarding on outgoing requests.
type outParams struct {
	Secrets []string `json:"secrets"`
	Header  string   `json:"header"`
	Prefix  string   `json:"prefix"`
}

type JWTAuthOut struct{}

func (j *JWTAuthOut) Name() string             { return "jwt" }
func (j *JWTAuthOut) RequiredParams() []string { return []string{"secrets"} }
func (j *JWTAuthOut) OptionalParams() []string { return []string{"header", "prefix"} }

func (j *JWTAuthOut) ParseParams(m map[string]interface{}) (interface{}, error) {
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
		p.Prefix = "Bearer "
	}
	return p, nil
}

func (j *JWTAuthOut) AddAuth(ctx context.Context, r *http.Request, p interface{}) error {
	cfg, ok := p.(*outParams)
	if !ok || len(cfg.Secrets) == 0 {
		return fmt.Errorf("invalid config")
	}
	tok, err := secrets.LoadRandomSecret(ctx, cfg.Secrets)
	if err != nil {
		return err
	}
	r.Header.Set(cfg.Header, cfg.Prefix+tok)
	return nil
}

func init() { authplugins.RegisterOutgoing(&JWTAuthOut{}) }
