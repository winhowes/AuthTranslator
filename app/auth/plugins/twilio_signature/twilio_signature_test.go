package twiliosignature

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func sign(urlStr string, form url.Values, secret string) string {
	keys := make([]string, 0, len(form))
	for k := range form {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	base := urlStr
	for _, k := range keys {
		for _, v := range form[k] {
			base += k + v
		}
	}
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(base))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestTwilioSignatureAuth(t *testing.T) {
	form := url.Values{"Body": []string{"hello"}}
	urlStr := "/path"
	sig := sign(urlStr, form, "tok")
	body := form.Encode()
	r := &http.Request{Method: "POST", URL: &url.URL{Path: urlStr}, Header: http.Header{
		"X-Twilio-Signature": []string{sig},
		"Content-Type":       []string{"application/x-www-form-urlencoded"},
	}, Body: io.NopCloser(strings.NewReader(body))}

	p := TwilioSignatureAuth{}
	t.Setenv("TOK", "tok")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
	p.StripAuth(r, cfg)
	if h := r.Header.Get("X-Twilio-Signature"); h != "" {
		t.Fatalf("expected header stripped, got %s", h)
	}
}

func TestTwilioSignatureAuthFail(t *testing.T) {
	form := url.Values{"Foo": []string{"bar"}}
	urlStr := "/cb"
	sig := sign(urlStr, form, "bad")
	body := form.Encode()
	r := &http.Request{Method: "POST", URL: &url.URL{Path: urlStr}, Header: http.Header{
		"X-Twilio-Signature": []string{sig},
		"Content-Type":       []string{"application/x-www-form-urlencoded"},
	}, Body: io.NopCloser(strings.NewReader(body))}
	p := TwilioSignatureAuth{}
	t.Setenv("TOK", "good")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}

func TestTwilioSignatureDefaults(t *testing.T) {
	p := TwilioSignatureAuth{}
	t.Setenv("S", "x")
	cfgI, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:S"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok := cfgI.(*twilioSigParams)
	if !ok {
		t.Fatalf("wrong type %T", cfgI)
	}
	if cfg.Header != "X-Twilio-Signature" {
		t.Fatalf("unexpected header %s", cfg.Header)
	}
}

func TestTwilioSignatureMissingHeader(t *testing.T) {
	r := &http.Request{Header: http.Header{}, URL: &url.URL{Path: "/p"}, Body: io.NopCloser(strings.NewReader(""))}
	p := TwilioSignatureAuth{}
	t.Setenv("S", "tok")
	cfg, _ := p.ParseParams(map[string]interface{}{"secrets": []string{"env:S"}})
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected failure without header")
	}
}

func TestTwilioSignatureParseParamsMissingSecrets(t *testing.T) {
	p := TwilioSignatureAuth{}
	if _, err := p.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestTwilioSignatureRequiredParams(t *testing.T) {
	p := TwilioSignatureAuth{}
	if got := p.RequiredParams(); len(got) != 1 || got[0] != "secrets" {
		t.Fatalf("unexpected required params %v", got)
	}
}

func TestTwilioSignatureOptionalParams(t *testing.T) {
	p := TwilioSignatureAuth{}
	if got := p.OptionalParams(); len(got) != 1 || got[0] != "header" {
		t.Fatalf("unexpected optional params %v", got)
	}
}

func TestTwilioSignatureInvalidParams(t *testing.T) {
	r := &http.Request{Header: http.Header{"X-Twilio-Signature": []string{"sig"}}, URL: &url.URL{Path: "/"}, Body: io.NopCloser(strings.NewReader(""))}
	p := TwilioSignatureAuth{}
	if p.Authenticate(context.Background(), r, nil) {
		t.Fatal("expected false for nil params")
	}
	if p.Authenticate(context.Background(), r, struct{}{}) {
		t.Fatal("expected false for wrong type")
	}
}

func TestTwilioSignatureStripAuthInvalidParams(t *testing.T) {
	r := &http.Request{Header: http.Header{"X-Twilio-Signature": []string{"sig"}}}
	p := TwilioSignatureAuth{}
	p.StripAuth(r, nil)
	if r.Header.Get("X-Twilio-Signature") == "" {
		t.Fatal("header should remain when params nil")
	}
	p.StripAuth(r, struct{}{})
	if r.Header.Get("X-Twilio-Signature") == "" {
		t.Fatal("header should remain when params wrong type")
	}
}

func TestTwilioSignatureMultipleSecrets(t *testing.T) {
	form := url.Values{"A": []string{"b"}}
	urlStr := "/m"
	sig := sign(urlStr, form, "good")
	body := form.Encode()
	r := &http.Request{Method: "POST", URL: &url.URL{Path: urlStr}, Header: http.Header{
		"X-Twilio-Signature": []string{sig},
		"Content-Type":       []string{"application/x-www-form-urlencoded"},
	}, Body: io.NopCloser(strings.NewReader(body))}

	p := TwilioSignatureAuth{}
	t.Setenv("BAD", "bad")
	t.Setenv("GOOD", "good")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:BAD", "env:GOOD"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected auth using second secret")
	}
}
