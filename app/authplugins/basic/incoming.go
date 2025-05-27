package basic

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/winhowes/AuthTranslator/app/authplugins"
	"github.com/winhowes/AuthTranslator/app/secrets"
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
	creds := dec
	for _, ref := range cfg.Secrets {
		sec, err := secrets.LoadSecret(ref)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(creds, []byte(sec)) == 1 {
			return true
		}
	}
	return false
}

// Identify returns the username from the Basic auth header when present.
func (b *BasicAuth) Identify(r *http.Request, p interface{}) (string, bool) {
	cfg, ok := p.(*inParams)
	if !ok {
		return "", false
	}
	header := r.Header.Get(cfg.Header)
	if !strings.HasPrefix(header, cfg.Prefix) {
		return "", false
	}
	enc := strings.TrimPrefix(header, cfg.Prefix)
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", false
	}
	creds := string(dec)
	if i := strings.IndexByte(creds, ':'); i > 0 {
		return creds[:i], true
	}
	return "", false
}

func init() { authplugins.RegisterIncoming(&BasicAuth{}) }
