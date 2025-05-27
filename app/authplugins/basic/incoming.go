package basic

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/winhowes/AuthTransformer/app/authplugins"
	"github.com/winhowes/AuthTransformer/app/secrets"
)

// BasicAuth validates HTTP Basic credentials from the request header.
type inParams struct {
	Secrets []string `json:"secrets"`
	Header  string   `json:"header"`
	Prefix  string   `json:"prefix"`
}

type BasicAuth struct{}

func (b *BasicAuth) Name() string             { return "basic" }
func (b *BasicAuth) RequiredParams() []string { return []string{"secrets"} }
func (b *BasicAuth) OptionalParams() []string { return []string{"header", "prefix"} }

func (b *BasicAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[inParams](m)
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

func (b *BasicAuth) Authenticate(r *http.Request, p interface{}) bool {
	cfg, ok := p.(*inParams)
	if !ok {
		return false
	}
	header := r.Header.Get(cfg.Header)
	if !strings.HasPrefix(header, cfg.Prefix) {
		return false
	}
	enc := strings.TrimPrefix(header, cfg.Prefix)
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return false
	}
	creds := string(dec)
	for _, ref := range cfg.Secrets {
		sec, err := secrets.LoadSecret(ref)
		if err == nil && creds == sec {
			return true
		}
	}
	return false
}

func init() { authplugins.RegisterIncoming(&BasicAuth{}) }
