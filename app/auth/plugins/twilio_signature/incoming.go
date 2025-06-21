package twiliosignature

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"

	"github.com/winhowes/AuthTranslator/app/auth"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

// twilioSigParams configures Twilio webhook signature validation.
type twilioSigParams struct {
	Secrets []string `json:"secrets"`
	Header  string   `json:"header"`
}

type TwilioSignatureAuth struct{}

func (t *TwilioSignatureAuth) Name() string { return "twilio_signature" }

func (t *TwilioSignatureAuth) RequiredParams() []string { return []string{"secrets"} }

func (t *TwilioSignatureAuth) OptionalParams() []string { return []string{"header"} }

func (t *TwilioSignatureAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[twilioSigParams](m)
	if err != nil {
		return nil, err
	}
	if len(p.Secrets) == 0 {
		return nil, fmt.Errorf("missing secrets")
	}
	if p.Header == "" {
		p.Header = "X-Twilio-Signature"
	}
	return p, nil
}

func canonicalString(r *http.Request) string {
	// Use the full URL including query string as seen by the proxy
	base := r.URL.String()
	// Include POST form parameters sorted by key
	if err := r.ParseForm(); err == nil {
		keys := make([]string, 0, len(r.PostForm))
		for k := range r.PostForm {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			vals := r.PostForm[k]
			for _, v := range vals {
				base += k + v
			}
		}
	}
	return base
}

func (t *TwilioSignatureAuth) Authenticate(ctx context.Context, r *http.Request, params interface{}) bool {
	cfg, ok := params.(*twilioSigParams)
	if !ok {
		return false
	}
	sig := r.Header.Get(cfg.Header)
	if sig == "" {
		return false
	}
	// Ensure body is read and restored for ParseForm
	if _, err := authplugins.GetBody(r); err != nil {
		return false
	}
	base := canonicalString(r)
	for _, ref := range cfg.Secrets {
		secret, err := secrets.LoadSecret(ctx, ref)
		if err != nil {
			continue
		}
		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write([]byte(base))
		expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(expected), []byte(sig)) {
			return true
		}
	}
	return false
}

// StripAuth removes the Twilio signature header from the request.
func (t *TwilioSignatureAuth) StripAuth(r *http.Request, params interface{}) {
	cfg, ok := params.(*twilioSigParams)
	if !ok {
		return
	}
	r.Header.Del(cfg.Header)
}

func init() { authplugins.RegisterIncoming(&TwilioSignatureAuth{}) }
