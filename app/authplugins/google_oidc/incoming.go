package googleoidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/winhowes/AuthTransformer/app/authplugins"
)

// inParams configures validation of incoming Google OIDC tokens.
type inParams struct {
	Audience string `json:"audience"`
	Header   string `json:"header"`
	Prefix   string `json:"prefix"`
}

// GoogleOIDCAuth validates Google issued ID tokens from incoming requests.
type GoogleOIDCAuth struct{}

func (g *GoogleOIDCAuth) Name() string { return "google_oidc" }

func (g *GoogleOIDCAuth) RequiredParams() []string { return []string{"audience"} }

func (g *GoogleOIDCAuth) OptionalParams() []string { return []string{"header", "prefix"} }

func (g *GoogleOIDCAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[inParams](m)
	if err != nil {
		return nil, err
	}
	if p.Audience == "" {
		return nil, fmt.Errorf("missing audience")
	}
	if p.Header == "" {
		p.Header = "Authorization"
	}
	if p.Prefix == "" {
		p.Prefix = "Bearer "
	}
	return p, nil
}

func parseToken(tok string) (map[string]interface{}, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	return claims, true
}

func matchAudience(claim interface{}, want string) bool {
	switch v := claim.(type) {
	case string:
		return v == want
	case []interface{}:
		for _, elem := range v {
			if s, ok := elem.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func (g *GoogleOIDCAuth) Authenticate(r *http.Request, params interface{}) bool {
	cfg, ok := params.(*inParams)
	if !ok {
		return false
	}
	header := r.Header.Get(cfg.Header)
	if !strings.HasPrefix(header, cfg.Prefix) {
		return false
	}
	token := strings.TrimPrefix(header, cfg.Prefix)
	claims, ok := parseToken(token)
	if !ok {
		return false
	}
	if aud, ok := claims["aud"]; !ok || !matchAudience(aud, cfg.Audience) {
		return false
	}
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return false
		}
	}
	return true
}

// Identify returns the token's subject claim when present.
func (g *GoogleOIDCAuth) Identify(r *http.Request, params interface{}) (string, bool) {
	cfg, ok := params.(*inParams)
	if !ok {
		return "", false
	}
	header := r.Header.Get(cfg.Header)
	if !strings.HasPrefix(header, cfg.Prefix) {
		return "", false
	}
	token := strings.TrimPrefix(header, cfg.Prefix)
	claims, ok := parseToken(token)
	if !ok {
		return "", false
	}
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", false
	}
	return sub, true
}

func init() { authplugins.RegisterIncoming(&GoogleOIDCAuth{}) }
