package basic

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"

	"github.com/winhowes/AuthTranslator/app/secrets"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestBasicOutgoingAddAuth(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := BasicAuthOut{}
	t.Setenv("CREDS", "user:pass")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:CREDS"}})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(context.Background(), r, cfg)
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if got := r.Header.Get("Authorization"); got != expected {
		t.Fatalf("expected %q, got %s", expected, got)
	}
}

func TestBasicOutgoingAddAuthMissingSecret(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := BasicAuthOut{}
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:MISSING"}})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(context.Background(), r, cfg)
	if got := r.Header.Get("Authorization"); got != "" {
		t.Fatalf("expected empty header, got %s", got)
	}
}

func TestBasicIncomingAuth(t *testing.T) {
	cred := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	r := &http.Request{Header: http.Header{"Authorization": []string{"Basic " + cred}}}
	p := BasicAuth{}
	t.Setenv("CREDS", "user:pass")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:CREDS"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}

	if id, ok := p.Identify(r, cfg); !ok || id != "user" {
		t.Fatalf("unexpected identifier %s", id)
	}
	p.StripAuth(r, cfg)
	if h := r.Header.Get("Authorization"); h != "" {
		t.Fatalf("expected header stripped, got %s", h)
	}
}

func TestBasicIncomingAuthFail(t *testing.T) {
	cred := base64.StdEncoding.EncodeToString([]byte("user:wrong"))
	r := &http.Request{Header: http.Header{"Authorization": []string{"Basic " + cred}}}
	p := BasicAuth{}
	t.Setenv("CREDS", "user:pass")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:CREDS"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}

func TestBasicIdentify(t *testing.T) {
	cred := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	r := &http.Request{Header: http.Header{"Authorization": []string{"Basic " + cred}}}
	p := BasicAuth{}
	t.Setenv("CREDS", "user:pass")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:CREDS"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
	id, ok := p.Identify(r, cfg)
	if !ok || id != "user" {
		t.Fatalf("unexpected id %s", id)
	}
}

func TestBasicPluginOptionalParams(t *testing.T) {
	in := BasicAuth{}
	out := BasicAuthOut{}
	if got := in.OptionalParams(); len(got) != 2 || got[0] != "header" || got[1] != "prefix" {
		t.Fatalf("unexpected optional params: %v", got)
	}
	if got := out.OptionalParams(); len(got) != 2 || got[0] != "header" || got[1] != "prefix" {
		t.Fatalf("unexpected optional params: %v", got)
	}
}
func TestBasicParseParamsDefaultsAndError(t *testing.T) {
	p := BasicAuth{}
	// defaults when header and prefix not provided
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:S"}})
	if err != nil {
		t.Fatal(err)
	}
	in := cfg.(*inParams)
	if in.Header != "Authorization" || in.Prefix != "Basic " {
		t.Fatalf("unexpected defaults: %v", in)
	}
	// error when secrets missing
	if _, err := p.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error for missing secrets")
	}
}

func TestBasicIdentifyFailures(t *testing.T) {
	p := BasicAuth{}
	t.Setenv("S", "user:pass")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:S"}})
	if err != nil {
		t.Fatal(err)
	}
	// invalid base64
	r := &http.Request{Header: http.Header{"Authorization": []string{"Basic $$"}}}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("auth should fail")
	}
	if id, ok := p.Identify(r, cfg); ok || id != "" {
		t.Fatalf("unexpected id %s", id)
	}
	// missing username
	cred := base64.StdEncoding.EncodeToString([]byte(":pass"))
	r = &http.Request{Header: http.Header{"Authorization": []string{"Basic " + cred}}}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("auth should fail")
	}
	if id, ok := p.Identify(r, cfg); ok || id != "" {
		t.Fatalf("expected empty id, got %s", id)
	}
}

// failPlugin simulates a failing secrets provider for error paths.
type failPlugin struct{}

func (failPlugin) Prefix() string { return "fail" }
func (failPlugin) Load(context.Context, string) (string, error) {
	return "", errors.New("fail")
}

func TestBasicCustomHeaderAndPrefix(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	out := BasicAuthOut{}
	t.Setenv("C", "u:p")
	ocfg, err := out.ParseParams(map[string]interface{}{
		"secrets": []string{"env:C"},
		"header":  "X-Auth",
		"prefix":  "Pre ",
	})
	if err != nil {
		t.Fatal(err)
	}
	out.AddAuth(context.Background(), r, ocfg)
	enc := base64.StdEncoding.EncodeToString([]byte("u:p"))
	expected := "Pre " + enc
	if got := r.Header.Get("X-Auth"); got != expected {
		t.Fatalf("expected %s, got %s", expected, got)
	}

	in := BasicAuth{}
	icfg, err := in.ParseParams(map[string]interface{}{
		"secrets": []string{"env:C"},
		"header":  "X-Auth",
		"prefix":  "Pre ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !in.Authenticate(context.Background(), r, icfg) {
		t.Fatal("expected authentication to succeed")
	}
	if id, ok := in.Identify(r, icfg); !ok || id != "u" {
		t.Fatalf("unexpected id %s", id)
	}
}

func TestBasicAddAuthInvalidParams(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	out := BasicAuthOut{}
	out.AddAuth(context.Background(), r, nil)
	if h := r.Header.Get("Authorization"); h != "" {
		t.Fatalf("expected empty header, got %s", h)
	}
	out.AddAuth(context.Background(), r, struct{}{})
	if h := r.Header.Get("Authorization"); h != "" {
		t.Fatalf("expected empty header, got %s", h)
	}
}

func TestBasicAuthenticateIdentifyInvalidParams(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	in := BasicAuth{}
	if in.Authenticate(context.Background(), r, nil) {
		t.Fatal("expected false for nil params")
	}
	if id, ok := in.Identify(r, nil); ok || id != "" {
		t.Fatalf("unexpected id %s", id)
	}
	if in.Authenticate(context.Background(), r, struct{}{}) {
		t.Fatal("expected false for wrong type")
	}
	if id, ok := in.Identify(r, struct{}{}); ok || id != "" {
		t.Fatalf("unexpected id %s", id)
	}
}

func TestBasicAddAuthSecretError(t *testing.T) {
	secrets.Register(failPlugin{})
	r := &http.Request{Header: http.Header{}}
	out := BasicAuthOut{}
	cfg := &outParams{Secrets: []string{"fail:o"}, Header: "Authorization"}
	out.AddAuth(context.Background(), r, cfg)
	if h := r.Header.Get("Authorization"); h != "" {
		t.Fatalf("expected empty header, got %s", h)
	}
}

func TestBasicParseParamsUnknownField(t *testing.T) {
	p := BasicAuth{}
	if _, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:S"}, "unknown": true}); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestBasicOutgoingAddAuthMultipleSecrets(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := BasicAuthOut{}
	t.Setenv("C1", "u1:p1")
	t.Setenv("C2", "u2:p2")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:C1", "env:C2"}})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAuth(context.Background(), r, cfg)
	got := r.Header.Get("Authorization")
	exp1 := "Basic " + base64.StdEncoding.EncodeToString([]byte("u1:p1"))
	exp2 := "Basic " + base64.StdEncoding.EncodeToString([]byte("u2:p2"))
	if got != exp1 && got != exp2 {
		t.Fatalf("unexpected header %s", got)
	}
}

func TestBasicIncomingPrefixMismatch(t *testing.T) {
	cred := base64.StdEncoding.EncodeToString([]byte("u:p"))
	r := &http.Request{Header: http.Header{"Authz": []string{"Basic " + cred}}}
	p := BasicAuth{}
	t.Setenv("C", "u:p")
	cfg, _ := p.ParseParams(map[string]interface{}{"secrets": []string{"env:C"}})
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail")
	}
	if id, ok := p.Identify(r, cfg); ok || id != "" {
		t.Fatalf("unexpected id %s", id)
	}
}

func TestBasicOutParseParamsMissingSecrets(t *testing.T) {
	o := BasicAuthOut{}
	if _, err := o.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error for missing secrets")
	}
}
func TestBasicPluginNamesAndRequiredParams(t *testing.T) {
	in := BasicAuth{}
	out := BasicAuthOut{}
	if in.Name() != "basic" || out.Name() != "basic" {
		t.Fatalf("unexpected names %s %s", in.Name(), out.Name())
	}
	if req := in.RequiredParams(); len(req) != 1 || req[0] != "secrets" {
		t.Fatalf("unexpected required params %v", req)
	}
	if req := out.RequiredParams(); len(req) != 1 || req[0] != "secrets" {
		t.Fatalf("unexpected required params %v", req)
	}
}

func TestBasicParseParamsUnknownFieldExtra(t *testing.T) {
	in := BasicAuth{}
	if _, err := in.ParseParams(map[string]interface{}{"secrets": []string{"env:S"}, "extra": true}); err == nil {
		t.Fatal("expected error for unknown field")
	}
	out := BasicAuthOut{}
	if _, err := out.ParseParams(map[string]interface{}{"secrets": []string{"env:S"}, "extra": true}); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestBasicAuthenticateSecretError(t *testing.T) {
	secrets.Register(failPlugin{})
	cred := base64.StdEncoding.EncodeToString([]byte("u:p"))
	r := &http.Request{Header: http.Header{"Authorization": []string{"Basic " + cred}}}
	p := BasicAuth{}
	cfg := &inParams{Secrets: []string{"fail:o"}, Header: "Authorization", Prefix: "Basic "}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}
