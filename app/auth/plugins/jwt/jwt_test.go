package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/winhowes/AuthTranslator/app/secrets"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func makeHS256Token(aud, sub, key string, exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payloadMap := map[string]interface{}{"aud": aud, "sub": sub, "exp": exp}
	payloadBytes, _ := json.Marshal(payloadMap)
	body := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := header + "." + body
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return signingInput + "." + sig
}

func TestJWTAuth(t *testing.T) {
	key := "secret"
	tok := makeHS256Token("aud1", "user1", key, time.Now().Add(time.Hour).Unix())
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	p := JWTAuth{}
	t.Setenv("KEY", key)
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:KEY"}, "audience": "aud1"})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
	id, ok := p.Identify(r, cfg)
	if !ok || id != "user1" {
		t.Fatalf("unexpected identifier %s", id)
	}
	p.StripAuth(r, cfg)
	if h := r.Header.Get("Authorization"); h != "" {
		t.Fatalf("expected header stripped, got %s", h)
	}
}

func TestJWTAuthFail(t *testing.T) {
	key := "secret"
	tok := makeHS256Token("aud1", "user1", key, time.Now().Add(-time.Hour).Unix())
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	p := JWTAuth{}
	t.Setenv("KEY", key)
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:KEY"}, "audience": "aud1"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}

func TestJWTOutgoingAddAuth(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := JWTAuthOut{}
	t.Setenv("TOK", "tok123")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer tok123" {
		t.Fatalf("expected 'Bearer tok123', got %s", got)
	}
}
func TestVerifyHS256(t *testing.T) {
	key := []byte("k")
	parts := strings.Split(makeHS256Token("a", "s", string(key), time.Now().Add(time.Hour).Unix()), ".")
	if !verifyHS256(parts, key) {
		t.Fatal("verifyHS256 should succeed")
	}
	bad := []string{parts[0], parts[1], parts[2] + "bad"}
	if verifyHS256(bad, key) {
		t.Fatal("verifyHS256 should fail")
	}
}

func TestJWTIdentifyNoSub(t *testing.T) {
	key := "s"
	// token without sub claim
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"a","exp":` + fmt.Sprint(time.Now().Add(time.Hour).Unix()) + `}`))
	sigInput := header + "." + payload
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	tok := sigInput + "." + sig
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	p := JWTAuth{}
	t.Setenv("K", key)
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:K"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("auth should pass")
	}
	if id, ok := p.Identify(r, cfg); ok || id != "" {
		t.Fatalf("expected empty id, got %s", id)
	}
}

func TestJWTParseParamsDefaultsAndError(t *testing.T) {
	p := JWTAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:X"}})
	if err != nil {
		t.Fatal(err)
	}
	in := cfg.(*inParams)
	if in.Header != "Authorization" || in.Prefix != "Bearer " {
		t.Fatalf("unexpected defaults: %v", in)
	}
	if _, err := p.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error")
	}
}

func makeRS256TokenClaims(t *testing.T, key *rsa.PrivateKey, aud, iss, sub string, exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	claims := map[string]interface{}{"aud": aud, "iss": iss, "sub": sub, "exp": exp}
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := header + "." + payload
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + signature
}

// failPlugin simulates a failing secrets provider.
type failPlugin struct{}

func (failPlugin) Prefix() string                               { return "fail" }
func (failPlugin) Load(context.Context, string) (string, error) { return "", fmt.Errorf("fail") }

func TestJWTAuthRS256(t *testing.T) {
	secrets.ClearCache()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tok := makeRS256TokenClaims(t, key, "aud", "iss", "user", time.Now().Add(time.Hour).Unix())
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	t.Setenv("PUB", string(pemBytes))
	p := JWTAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:PUB"}, "audience": "aud", "issuer": "iss"})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
	if id, ok := p.Identify(r, cfg); !ok || id != "user" {
		t.Fatalf("unexpected id %s", id)
	}
}

func TestJWTAuthRS256PKCS1PublicKey(t *testing.T) {
	secrets.ClearCache()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tok := makeRS256TokenClaims(t, key, "aud", "iss", "user", time.Now().Add(time.Hour).Unix())
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})
	t.Setenv("PKCS1", string(pemBytes))
	p := JWTAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:PKCS1"}, "audience": "aud", "issuer": "iss"})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed with RSA PUBLIC KEY")
	}
}

func TestJWTAuthUnsupportedAlgo(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	tok := header + "." + payload + ".sig"
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	p := JWTAuth{}
	t.Setenv("K", "key")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:K"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected auth to fail")
	}
}

func TestJWTOutgoingEdgeCases(t *testing.T) {
	secrets.ClearCache()
	secrets.Register(failPlugin{})
	p := JWTAuthOut{}
	r := &http.Request{Header: http.Header{}}
	// bad params type
	if err := p.AddAuth(context.Background(), r, struct{}{}); err == nil {
		t.Fatal("expected error")
	}
	if h := r.Header.Get("Authorization"); h != "" {
		t.Fatalf("expected empty header, got %s", h)
	}
	// missing secrets
	r = &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, &outParams{}); err == nil {
		t.Fatal("expected error")
	}
	if h := r.Header.Get("Authorization"); h != "" {
		t.Fatalf("expected empty header, got %s", h)
	}
	// secret load error
	r = &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, &outParams{Secrets: []string{"fail:oops"}}); err == nil {
		t.Fatal("expected error")
	}
	if h := r.Header.Get("Authorization"); h != "" {
		t.Fatalf("expected empty header, got %s", h)
	}
	// custom header/prefix success
	t.Setenv("TOK", "t1")
	r = &http.Request{Header: http.Header{}}
	cfg := &outParams{Secrets: []string{"env:TOK"}, Header: "Authz", Prefix: "pre "}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("Authz"); got != "pre t1" {
		t.Fatalf("expected 'pre t1', got %s", got)
	}
}

func TestJWTOutgoingParseParams(t *testing.T) {
	p := JWTAuthOut{}
	t.Setenv("TOK", "tok")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK"}})
	if err != nil {
		t.Fatal(err)
	}
	out := cfg.(*outParams)
	if out.Header != "Authorization" || out.Prefix != "Bearer " {
		t.Fatalf("unexpected defaults: %#v", out)
	}
	if _, err := p.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error for missing secrets")
	}
	if req := p.RequiredParams(); len(req) != 1 || req[0] != "secrets" {
		t.Fatalf("unexpected required params: %v", req)
	}
	if opt := p.OptionalParams(); len(opt) != 2 || opt[0] != "header" {
		t.Fatalf("unexpected optional params: %v", opt)
	}
}

func makeHS256ClaimsToken(key string, claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := header + "." + payload
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return signingInput + "." + sig
}

func TestJWTAuthAudienceIssuerMismatch(t *testing.T) {
	key := "secret"
	claims := map[string]interface{}{
		"aud": "aud1",
		"iss": "iss1",
		"sub": "sub",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok := makeHS256ClaimsToken(key, claims)
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	p := JWTAuth{}
	t.Setenv("K", key)
	cfgGood, _ := p.ParseParams(map[string]interface{}{"secrets": []string{"env:K"}, "audience": "aud1", "issuer": "iss1"})
	if !p.Authenticate(context.Background(), r, cfgGood) {
		t.Fatal("expected success")
	}
	cfgAud, _ := p.ParseParams(map[string]interface{}{"secrets": []string{"env:K"}, "audience": "other"})
	if p.Authenticate(context.Background(), r, cfgAud) {
		t.Fatal("audience mismatch should fail")
	}
	cfgIss, _ := p.ParseParams(map[string]interface{}{"secrets": []string{"env:K"}, "issuer": "other"})
	if p.Authenticate(context.Background(), r, cfgIss) {
		t.Fatal("issuer mismatch should fail")
	}
}

func TestJWTAuthSecretLoadFail(t *testing.T) {
	secrets.ClearCache()
	secrets.Register(failPlugin{})
	tok := makeHS256Token("aud", "u", "key", time.Now().Add(time.Hour).Unix())
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	p := JWTAuth{}
	cfg := &inParams{Secrets: []string{"fail:oops"}, Header: "Authorization", Prefix: "Bearer "}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected failure when secret load fails")
	}
}

func TestJWTIdentifyBadInput(t *testing.T) {
	p := JWTAuth{}
	cfg := &inParams{Header: "Authorization", Prefix: "Bearer "}
	r := &http.Request{Header: http.Header{"Authorization": []string{"tok"}}}
	if id, ok := p.Identify(r, cfg); ok || id != "" {
		t.Fatalf("expected empty id for missing prefix, got %s", id)
	}
	r = &http.Request{Header: http.Header{"Authorization": []string{"Bearer bad"}}}
	if id, ok := p.Identify(r, cfg); ok || id != "" {
		t.Fatalf("expected empty id for malformed token, got %s", id)
	}
}

func TestJWTAuthCustomHeaderPrefix(t *testing.T) {
	secrets.ClearCache()
	key := "s"
	claims := map[string]interface{}{
		"aud": "a",
		"sub": "user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok := makeHS256ClaimsToken(key, claims)
	r := &http.Request{Header: http.Header{"Authz": []string{"Token " + tok}}}
	p := JWTAuth{}
	t.Setenv("K", key)
	cfg, err := p.ParseParams(map[string]interface{}{
		"secrets": []string{"env:K"},
		"header":  "Authz",
		"prefix":  "Token ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
	if id, ok := p.Identify(r, cfg); !ok || id != "user" {
		t.Fatalf("unexpected id %s", id)
	}
}

func TestJWTAuthNoExpOrInvalidExp(t *testing.T) {
	secrets.ClearCache()
	key := "sec"
	p := JWTAuth{}
	t.Setenv("K", key)
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:K"}})
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]interface{}{"aud": "a", "sub": "u"}
	tok := makeHS256ClaimsToken(key, claims)
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("missing exp should still authenticate")
	}

	claims["exp"] = "notanumber"
	tok = makeHS256ClaimsToken(key, claims)
	r = &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("non numeric exp should authenticate")
	}
}

func TestJWTOutgoingAddAuthMultipleSecrets(t *testing.T) {
	secrets.ClearCache()
	r := &http.Request{Header: http.Header{}}
	p := JWTAuthOut{}
	t.Setenv("TOK1", "tok1")
	t.Setenv("TOK2", "tok2")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:TOK1", "env:TOK2"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	got := r.Header.Get("Authorization")
	if got != "Bearer tok1" && got != "Bearer tok2" {
		t.Fatalf("unexpected header %s", got)
	}
}

func TestJWTAuthMultipleSecrets(t *testing.T) {
	secrets.ClearCache()
	keyGood := "good"
	keyBad := "bad"
	tok := makeHS256Token("aud", "id", keyGood, time.Now().Add(time.Hour).Unix())
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	p := JWTAuth{}
	t.Setenv("GOOD", keyGood)
	t.Setenv("BAD", keyBad)
	cfg, err := p.ParseParams(map[string]interface{}{
		"secrets":  []string{"env:BAD", "env:GOOD"},
		"audience": "aud",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed with second secret")
	}
	if id, ok := p.Identify(r, cfg); !ok || id != "id" {
		t.Fatalf("unexpected id %s", id)
	}
}

func TestJWTParseParamsUnknownField(t *testing.T) {
	p := JWTAuth{}
	if _, err := p.ParseParams(map[string]interface{}{
		"secrets": []string{"env:X"},
		"unknown": true,
	}); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestJWTAuthenticateInvalidParams(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"tok"}}}
	p := JWTAuth{}
	if p.Authenticate(context.Background(), r, struct{}{}) {
		t.Fatal("expected failure for wrong params")
	}
}

func TestJWTIdentifyWrongParams(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"tok"}}}
	p := JWTAuth{}
	if id, ok := p.Identify(r, 5); ok || id != "" {
		t.Fatalf("unexpected id %s", id)
	}
}

func TestJWTOutgoingParseParamsUnknownField(t *testing.T) {
	p := JWTAuthOut{}
	if _, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:X"}, "extra": true}); err == nil {
		t.Fatal("expected error")
	}
}
func TestJWTStripAuthInvalidParams(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"tok"}}}
	j := JWTAuth{}
	j.StripAuth(r, nil)
	if r.Header.Get("Authorization") == "" {
		t.Fatal("header should remain when params nil")
	}
	j.StripAuth(r, struct{}{})
	if r.Header.Get("Authorization") == "" {
		t.Fatal("header should remain when params wrong type")
	}
}

func TestJWTAuthenticatePrefixMismatchAndParseError(t *testing.T) {
	key := "k"
	tok := makeHS256Token("a", "u", key, time.Now().Add(time.Hour).Unix())
	r := &http.Request{Header: http.Header{"Authorization": []string{"Token " + tok}}}
	j := JWTAuth{}
	t.Setenv("K", key)
	cfg, _ := j.ParseParams(map[string]interface{}{"secrets": []string{"env:K"}, "prefix": "Bearer ", "header": "Authorization"})
	if j.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected prefix mismatch to fail")
	}
	r.Header.Set("Authorization", "Bearer badtoken")
	if j.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected malformed token to fail")
	}
}

func TestVerifyRS256FailurePaths(t *testing.T) {
	parts := []string{"a", "b", "sig"}
	if verifyRS256(parts, []byte("notpem")) {
		t.Fatal("expected false for bad pem")
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("bad")})
	if verifyRS256(parts, pemData) {
		t.Fatal("expected false for parse error")
	}
	pemData = pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: []byte("bad")})
	if verifyRS256(parts, pemData) {
		t.Fatal("expected false for RSA PUBLIC KEY parse error")
	}
	pemData = pem.EncodeToMemory(&pem.Block{Type: "UNHANDLED", Bytes: []byte("bad")})
	if verifyRS256(parts, pemData) {
		t.Fatal("expected false for unsupported block type")
	}
	eckey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&eckey.PublicKey)
	pemData = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	if verifyRS256(parts, pemData) {
		t.Fatal("expected false for non-RSA key")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err = x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemData = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	badParts := []string{parts[0], parts[1], "!!"}
	if verifyRS256(badParts, pemData) {
		t.Fatal("expected false for bad signature")
	}
}
