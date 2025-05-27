package hmacsig

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"

	"github.com/winhowes/AuthTranslator/app/authplugins"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

// inParams configures validation of generic HMAC signatures.
// Algo may be one of sha1, sha256 or sha512.
type inParams struct {
	Secrets []string `json:"secrets"`
	Header  string   `json:"header"`
	Prefix  string   `json:"prefix"`
	Algo    string   `json:"algo"`
}

type HMACSignatureAuth struct{}

func (h *HMACSignatureAuth) Name() string             { return "hmac_signature" }
func (h *HMACSignatureAuth) RequiredParams() []string { return []string{"secrets"} }
func (h *HMACSignatureAuth) OptionalParams() []string { return []string{"header", "prefix", "algo"} }

func hashFunc(algo string) (func() hash.Hash, error) {
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

func (h *HMACSignatureAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[inParams](m)
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
	if _, err := hashFunc(p.Algo); err != nil {
		return nil, err
	}
	return p, nil
}

func (h *HMACSignatureAuth) Authenticate(r *http.Request, params interface{}) bool {
	cfg, ok := params.(*inParams)
	if !ok {
		return false
	}
	newHash, err := hashFunc(cfg.Algo)
	if err != nil {
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	sig := r.Header.Get(cfg.Header)
	if sig == "" {
		return false
	}
	for _, ref := range cfg.Secrets {
		secret, err := secrets.LoadSecret(ref)
		if err != nil {
			continue
		}
		mac := hmac.New(newHash, []byte(secret))
		mac.Write(body)
		expected := cfg.Prefix + hex.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(expected), []byte(sig)) {
			return true
		}
	}
	return false
}

func init() { authplugins.RegisterIncoming(&HMACSignatureAuth{}) }
