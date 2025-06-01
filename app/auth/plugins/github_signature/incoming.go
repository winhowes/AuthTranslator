package githubsignature

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/winhowes/AuthTranslator/app/auth"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

// githubSigParams configures GitHub webhook signature validation.
type githubSigParams struct {
	Secrets []string `json:"secrets"`
	Header  string   `json:"header"`
	Prefix  string   `json:"prefix"`
}

type GitHubSignatureAuth struct{}

func (g *GitHubSignatureAuth) Name() string { return "github_signature" }

func (g *GitHubSignatureAuth) RequiredParams() []string { return []string{"secrets"} }

func (g *GitHubSignatureAuth) OptionalParams() []string { return []string{"header", "prefix"} }

func (g *GitHubSignatureAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[githubSigParams](m)
	if err != nil {
		return nil, err
	}
	if len(p.Secrets) == 0 {
		return nil, fmt.Errorf("missing secrets")
	}
	if p.Header == "" {
		p.Header = "X-Hub-Signature-256"
	}
	if p.Prefix == "" {
		p.Prefix = "sha256="
	}
	return p, nil
}

func (g *GitHubSignatureAuth) Authenticate(ctx context.Context, r *http.Request, p interface{}) bool {
	cfg, ok := p.(*githubSigParams)
	if !ok {
		return false
	}
	body, err := authplugins.GetBody(r)
	if err != nil {
		return false
	}
	sig := r.Header.Get(cfg.Header)
	if sig == "" {
		return false
	}
	for _, ref := range cfg.Secrets {
		secret, err := secrets.LoadSecret(ctx, ref)
		if err != nil {
			continue
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		expected := cfg.Prefix + hex.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(expected), []byte(sig)) {
			return true
		}
	}
	return false
}

// StripAuth removes the GitHub signature header from the request.
func (g *GitHubSignatureAuth) StripAuth(r *http.Request, p interface{}) {
	cfg, ok := p.(*githubSigParams)
	if !ok {
		return
	}
	r.Header.Del(cfg.Header)
}

func init() { authplugins.RegisterIncoming(&GitHubSignatureAuth{}) }
