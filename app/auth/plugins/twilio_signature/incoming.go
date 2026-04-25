package twiliosignature

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"

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

func canonicalString(r *http.Request, body []byte) string {
	// Use the full URL including query string as seen by the proxy
	base := r.URL.String()

	form, ok := parseCanonicalForm(r, body)
	if !ok || len(form) == 0 {
		return base
	}

	keys := make([]string, 0, len(form))
	totalLen := len(base)
	for k, vals := range form {
		keys = append(keys, k)
		for _, v := range vals {
			totalLen += len(k) + len(v)
		}
	}
	sort.Strings(keys)

	var builder strings.Builder
	builder.Grow(totalLen)
	builder.WriteString(base)
	for _, k := range keys {
		vals := form[k]
		for _, v := range vals {
			builder.WriteString(k)
			builder.WriteString(v)
		}
	}
	return builder.String()
}

func parseCanonicalForm(r *http.Request, body []byte) (url.Values, bool) {
	if r.PostForm != nil {
		return r.PostForm, true
	}

	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return nil, false
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return nil, false
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, false
	}
	return form, true
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
	// Use the shared body cache so signature validation does not consume the
	// request body before the proxy forwards it upstream.
	body, err := authplugins.GetBody(r)
	if err != nil {
		return false
	}
	base := canonicalString(r, body)
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
