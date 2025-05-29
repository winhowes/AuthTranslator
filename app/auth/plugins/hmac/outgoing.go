package hmacsig

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"

	"github.com/winhowes/AuthTranslator/app/auth"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

// outParams configures HMAC signing of outgoing requests.
// Algo may be one of sha1, sha256 or sha512.
type outParams struct {
	Secrets []string `json:"secrets"`
	Header  string   `json:"header"`
	Prefix  string   `json:"prefix"`
	Algo    string   `json:"algo"`
}

type HMACSignature struct{}

func (h *HMACSignature) Name() string             { return "hmac_signature" }
func (h *HMACSignature) RequiredParams() []string { return []string{"secrets"} }
func (h *HMACSignature) OptionalParams() []string { return []string{"header", "prefix", "algo"} }

func hashFuncOut(algo string) (func() hash.Hash, error) {
	switch algo {
	case "sha1":
		return sha1.New, nil
	case "sha256", "":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported algo %s", algo)
	}
}

func (h *HMACSignature) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[outParams](m)
	if err != nil {
		return nil, err
	}
	if len(p.Secrets) == 0 {
		return nil, fmt.Errorf("missing secrets")
	}
	if p.Header == "" {
		p.Header = "X-Signature"
	}
	if p.Algo == "" {
		p.Algo = "sha256"
	}
	if _, err := hashFuncOut(p.Algo); err != nil {
		return nil, err
	}
	return p, nil
}

func (h *HMACSignature) AddAuth(ctx context.Context, r *http.Request, params interface{}) {
	cfg, ok := params.(*outParams)
	if !ok || len(cfg.Secrets) == 0 {
		return
	}
	newHash, err := hashFuncOut(cfg.Algo)
	if err != nil {
		return
	}
	body, err := authplugins.GetBody(r)
	if err != nil {
		return
	}
	secret, err := secrets.LoadRandomSecret(ctx, cfg.Secrets)
	if err != nil {
		return
	}
	mac := hmac.New(newHash, []byte(secret))
	mac.Write(body)
	sig := cfg.Prefix + hex.EncodeToString(mac.Sum(nil))
	r.Header.Set(cfg.Header, sig)
}

func init() { authplugins.RegisterOutgoing(&HMACSignature{}) }
