package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/winhowes/AuthTransformer/app/authplugins"
	"github.com/winhowes/AuthTransformer/app/secrets"
)

// inParams configures JWT validation.
type inParams struct {
	Secrets  []string `json:"secrets"`
	Audience string   `json:"audience"`
	Issuer   string   `json:"issuer"`
	Header   string   `json:"header"`
	Prefix   string   `json:"prefix"`
}

type JWTAuth struct{}

func (j *JWTAuth) Name() string             { return "jwt" }
func (j *JWTAuth) RequiredParams() []string { return []string{"secrets"} }
func (j *JWTAuth) OptionalParams() []string {
	return []string{"audience", "issuer", "header", "prefix"}
}

func (j *JWTAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
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
		p.Prefix = "Bearer "
	}
	return p, nil
}

func parseHeaderPayload(tok string) (header map[string]interface{}, payload map[string]interface{}, parts []string, ok bool) {
	parts = strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, nil, nil, false
	}
	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, false
	}
	if err := json.Unmarshal(hBytes, &header); err != nil {
		return nil, nil, nil, false
	}
	pBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, false
	}
	if err := json.Unmarshal(pBytes, &payload); err != nil {
		return nil, nil, nil, false
	}
	return header, payload, parts, true
}

func verifyHS256(parts []string, key []byte) bool {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(parts[0] + "." + parts[1]))
	sig := h.Sum(nil)
	expected := base64.RawURLEncoding.EncodeToString(sig)
	return hmac.Equal([]byte(expected), []byte(parts[2]))
}

func verifyRS256(parts []string, pemData []byte) bool {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return false
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sig) == nil
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

func (j *JWTAuth) Authenticate(r *http.Request, p interface{}) bool {
	cfg, ok := p.(*inParams)
	if !ok {
		return false
	}
	headerVal := r.Header.Get(cfg.Header)
	if !strings.HasPrefix(headerVal, cfg.Prefix) {
		return false
	}
	token := strings.TrimPrefix(headerVal, cfg.Prefix)
	header, claims, parts, ok := parseHeaderPayload(token)
	if !ok {
		return false
	}
	alg, _ := header["alg"].(string)
	verified := false
	for _, ref := range cfg.Secrets {
		key, err := secrets.LoadSecret(ref)
		if err != nil {
			continue
		}
		switch alg {
		case "HS256":
			if verifyHS256(parts, []byte(key)) {
				verified = true
			}
		case "RS256":
			if verifyRS256(parts, []byte(key)) {
				verified = true
			}
		default:
			return false
		}
		if verified {
			break
		}
	}
	if !verified {
		return false
	}
	if aud := cfg.Audience; aud != "" {
		if claim, ok := claims["aud"]; !ok || !matchAudience(claim, aud) {
			return false
		}
	}
	if iss := cfg.Issuer; iss != "" {
		if claim, ok := claims["iss"].(string); !ok || claim != iss {
			return false
		}
	}
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return false
		}
	}
	return true
}

func (j *JWTAuth) Identify(r *http.Request, p interface{}) (string, bool) {
	cfg, ok := p.(*inParams)
	if !ok {
		return "", false
	}
	headerVal := r.Header.Get(cfg.Header)
	if !strings.HasPrefix(headerVal, cfg.Prefix) {
		return "", false
	}
	token := strings.TrimPrefix(headerVal, cfg.Prefix)
	_, claims, _, ok := parseHeaderPayload(token)
	if !ok {
		return "", false
	}
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", false
	}
	return sub, true
}

func init() { authplugins.RegisterIncoming(&JWTAuth{}) }
