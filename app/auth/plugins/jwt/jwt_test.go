package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

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
	p.AddAuth(context.Background(), r, cfg)
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
