package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	_ "github.com/winhowes/AuthTransformer/app/secrets/plugins"
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
	if !p.Authenticate(r, cfg) {
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
	if p.Authenticate(r, cfg) {
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
	p.AddAuth(r, cfg)
	if got := r.Header.Get("Authorization"); got != "Bearer tok123" {
		t.Fatalf("expected 'Bearer tok123', got %s", got)
	}
}
