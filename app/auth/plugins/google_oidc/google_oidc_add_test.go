package googleoidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGoogleOIDCParseParamsCustomAndMissing(t *testing.T) {
	p := GoogleOIDC{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"audience": "a",
		"header":   "H",
		"prefix":   "Pre ",
	})
	if err != nil {
		t.Fatal(err)
	}
	pcfg := cfg.(*googleOIDCParams)
	if pcfg.Header != "H" || pcfg.Prefix != "Pre " || pcfg.Audience != "a" {
		t.Fatalf("unexpected config %#v", pcfg)
	}
	if _, err := p.ParseParams(map[string]interface{}{"header": "H"}); err == nil {
		t.Fatal("expected error for missing audience")
	}
}

func TestGoogleOIDCAuthParseParamsCustomAndMissing(t *testing.T) {
	g := GoogleOIDCAuth{}
	cfg, err := g.ParseParams(map[string]interface{}{
		"audience": "a",
		"header":   "X",
		"prefix":   "P ",
	})
	if err != nil {
		t.Fatal(err)
	}
	icfg := cfg.(*inParams)
	if icfg.Header != "X" || icfg.Prefix != "P " || icfg.Audience != "a" {
		t.Fatalf("unexpected config %#v", icfg)
	}
	if _, err := g.ParseParams(map[string]interface{}{"header": "X"}); err == nil {
		t.Fatal("expected error for missing audience")
	}
}

func TestFetchKeysExpiresHeader(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	kid := "exp1"
	jwks := jwksForKey(&key.PublicKey, kid)
	exp := time.Now().Add(90 * time.Minute).Round(time.Second).UTC()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Expires", exp.Format(http.TimeFormat))
		fmt.Fprint(w, jwks)
	}))
	defer ts.Close()

	oldURL := CertsURL
	CertsURL = ts.URL
	defer func() { CertsURL = oldURL }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	keyCache.mu.Lock()
	oldKeys := keyCache.keys
	oldExp := keyCache.expiry
	keyCache.keys = nil
	keyCache.expiry = time.Time{}
	keyCache.mu.Unlock()
	defer func() {
		keyCache.mu.Lock()
		keyCache.keys = oldKeys
		keyCache.expiry = oldExp
		keyCache.mu.Unlock()
	}()

	if err := fetchKeys(); err != nil {
		t.Fatal(err)
	}
	keyCache.mu.RLock()
	_, ok := keyCache.keys[kid]
	gotExp := keyCache.expiry
	keyCache.mu.RUnlock()
	if !ok {
		t.Fatal("key not cached")
	}
	if gotExp.Before(exp.Add(-time.Second)) || gotExp.After(exp.Add(time.Second)) {
		t.Fatalf("unexpected expiry %v", gotExp)
	}
}

func TestGetKeyTriggersFetch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	kid := "fetch"
	jwks := jwksForKey(&key.PublicKey, kid)
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		fmt.Fprint(w, jwks)
	}))
	defer ts.Close()

	oldURL := CertsURL
	CertsURL = ts.URL
	defer func() { CertsURL = oldURL }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	keyCache.mu.Lock()
	oldKeys := keyCache.keys
	oldExp := keyCache.expiry
	keyCache.keys = map[string]*rsa.PublicKey{"old": nil}
	keyCache.expiry = time.Now().Add(-time.Minute)
	keyCache.mu.Unlock()
	defer func() {
		keyCache.mu.Lock()
		keyCache.keys = oldKeys
		keyCache.expiry = oldExp
		keyCache.mu.Unlock()
	}()

	k, err := getKey(kid)
	if err != nil || !called || k == nil {
		t.Fatalf("fetch did not occur or error %v", err)
	}
}

func TestGoogleOIDCAuthenticateFailures(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	kid := "af"
	jwks := jwksForKey(&key.PublicKey, kid)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, jwks)
	}))
	defer ts.Close()

	oldURL := CertsURL
	CertsURL = ts.URL
	defer func() { CertsURL = oldURL }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()
	keyCache.mu.Lock()
	oldKeys := keyCache.keys
	oldExp := keyCache.expiry
	keyCache.keys = nil
	keyCache.expiry = time.Time{}
	keyCache.mu.Unlock()
	defer func() {
		keyCache.mu.Lock()
		keyCache.keys = oldKeys
		keyCache.expiry = oldExp
		keyCache.mu.Unlock()
	}()

	tok := makeToken("good", "sub", time.Now().Add(time.Hour).Unix(), key, kid)
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bad " + tok}}}
	auth := GoogleOIDCAuth{}
	cfg, _ := auth.ParseParams(map[string]interface{}{"audience": "good", "prefix": "Bearer "})
	if auth.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected prefix mismatch failure")
	}
	r.Header.Set("Authorization", "Bearer "+tok)
	cfg2, _ := auth.ParseParams(map[string]interface{}{"audience": "other"})
	if auth.Authenticate(context.Background(), r, cfg2) {
		t.Fatal("expected audience mismatch failure")
	}
}

func TestGoogleOIDCIdentifyNoSub(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	kid := "nosub"
	jwks := jwksForKey(&key.PublicKey, kid)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, jwks)
	}))
	defer ts.Close()

	oldURL := CertsURL
	CertsURL = ts.URL
	defer func() { CertsURL = oldURL }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()
	keyCache.mu.Lock()
	oldKeys := keyCache.keys
	oldExp := keyCache.expiry
	keyCache.keys = nil
	keyCache.expiry = time.Time{}
	keyCache.mu.Unlock()
	defer func() {
		keyCache.mu.Lock()
		keyCache.keys = oldKeys
		keyCache.expiry = oldExp
		keyCache.mu.Unlock()
	}()

	headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadBytes, _ := json.Marshal(map[string]interface{}{"aud": "a", "exp": time.Now().Add(time.Hour).Unix()})
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signInput := header + "." + payload
	h := sha256.Sum256([]byte(signInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	tok := signInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	auth := GoogleOIDCAuth{}
	cfg, _ := auth.ParseParams(map[string]interface{}{"audience": "a"})
	if id, ok := auth.Identify(r, cfg); ok || id != "" {
		t.Fatal("expected identify failure")
	}
}
