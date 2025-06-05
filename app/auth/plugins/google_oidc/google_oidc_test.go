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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestGoogleOIDCAddAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Errorf("missing metadata header")
		}
		if q := r.URL.Query().Get("audience"); q != "testaud" {
			t.Errorf("unexpected audience %s", q)
		}
		fmt.Fprint(w, "tok123")
	}))
	defer ts.Close()

	oldHost := MetadataHost
	MetadataHost = ts.URL
	defer func() { MetadataHost = oldHost }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	p := GoogleOIDC{}
	cfg, err := p.ParseParams(map[string]interface{}{"audience": "testaud"})
	if err != nil {
		t.Fatal(err)
	}

	r := &http.Request{Header: http.Header{}}
	p.AddAuth(context.Background(), r, cfg)
	if got := r.Header.Get("Authorization"); got != "Bearer tok123" {
		t.Fatalf("expected 'Bearer tok123', got %s", got)
	}
}

func TestGoogleOIDCDefaults(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tok")
	}))
	defer ts.Close()

	oldHost := MetadataHost
	MetadataHost = ts.URL
	defer func() { MetadataHost = oldHost }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	p := GoogleOIDC{}
	cfg, err := p.ParseParams(map[string]interface{}{"audience": "aud"})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{}}
	p.AddAuth(context.Background(), r, cfg)
	if got := r.Header.Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("unexpected header %s", got)
	}
}

func TestGoogleOIDCAddAuthFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	oldHost := MetadataHost
	MetadataHost = ts.URL
	defer func() { MetadataHost = oldHost }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	p := GoogleOIDC{}
	cfg, err := p.ParseParams(map[string]interface{}{"audience": "failaud"})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{}}
	p.AddAuth(context.Background(), r, cfg)
	if got := r.Header.Get("Authorization"); got != "" {
		t.Fatalf("expected empty header, got %s", got)
	}
}

type failTransport struct{ called bool }

func (ft *failTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ft.called = true
	return nil, fmt.Errorf("called")
}

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, fmt.Errorf("err") }
func (errReadCloser) Close() error             { return nil }

func TestGoogleOIDCAddAuthCache(t *testing.T) {
	tokenCache.Lock()
	tokenCache.m = make(map[string]cachedToken)
	tokenCache.Unlock()
	defer func() {
		tokenCache.Lock()
		tokenCache.m = make(map[string]cachedToken)
		tokenCache.Unlock()
	}()

	setCachedToken("aud", "cachedtok", time.Now().Add(time.Hour))

	ft := &failTransport{}
	oldClient := HTTPClient
	HTTPClient = &http.Client{Transport: ft}
	defer func() { HTTPClient = oldClient }()

	p := GoogleOIDC{}
	cfg, err := p.ParseParams(map[string]interface{}{"audience": "aud"})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{}}
	p.AddAuth(context.Background(), r, cfg)
	if got := r.Header.Get("Authorization"); got != "Bearer cachedtok" {
		t.Fatalf("unexpected header %s", got)
	}
	if ft.called {
		t.Fatalf("HTTP client should not have been called")
	}
}

func TestGoogleOIDCAddAuthExpiredCache(t *testing.T) {
	tokenCache.Lock()
	tokenCache.m = map[string]cachedToken{"aud": {token: "old", exp: time.Now().Add(-time.Minute)}}
	tokenCache.Unlock()
	defer func() {
		tokenCache.Lock()
		tokenCache.m = make(map[string]cachedToken)
		tokenCache.Unlock()
	}()

	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		fmt.Fprint(w, "newtok")
	}))
	defer ts.Close()

	oldHost := MetadataHost
	MetadataHost = ts.URL
	defer func() { MetadataHost = oldHost }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	p := GoogleOIDC{}
	cfg, err := p.ParseParams(map[string]interface{}{"audience": "aud"})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{}}
	p.AddAuth(context.Background(), r, cfg)
	if !called {
		t.Fatal("expected HTTP call for expired cache")
	}
	if got := r.Header.Get("Authorization"); got != "Bearer newtok" {
		t.Fatalf("unexpected header %s", got)
	}
}

func TestGoogleOIDCParseParamsUnknownField(t *testing.T) {
	p := GoogleOIDC{}
	if _, err := p.ParseParams(map[string]interface{}{"audience": "a", "bad": true}); err == nil {
		t.Fatal("expected error")
	}
	a := GoogleOIDCAuth{}
	if _, err := a.ParseParams(map[string]interface{}{"audience": "a", "extra": 1}); err == nil {
		t.Fatal("expected error")
	}
}

func makeToken(aud, sub string, exp int64, key *rsa.PrivateKey, kid string) string {
	headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadBytes, _ := json.Marshal(map[string]interface{}{"aud": aud, "sub": sub, "exp": exp})
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := header + "." + payload
	h := sha256.Sum256([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jwksForKey(pub *rsa.PublicKey, kid string) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := make([]byte, 0)
	e := pub.E
	for e > 0 {
		eBytes = append([]byte{byte(e % 256)}, eBytes...)
		e /= 256
	}
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"%s","alg":"RS256","n":"%s","e":"%s"}]}`, kid, n, eStr)
}

func TestGoogleOIDCIncomingAuth(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	kid := "k1"
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

	tok := makeToken("aud1", "user1", time.Now().Add(time.Hour).Unix(), key, kid)
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	p := GoogleOIDCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"audience": "aud1"})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
	if id, ok := p.Identify(r, cfg); !ok || id != "user1" {
		t.Fatalf("unexpected identifier %s", id)
	}
	p.StripAuth(r, cfg)
	if h := r.Header.Get("Authorization"); h != "" {
		t.Fatalf("expected header stripped, got %s", h)
	}
}

func TestGoogleOIDCIncomingAuthFail(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	kid := "k2"
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

	tok := makeToken("aud2", "u", time.Now().Add(-time.Hour).Unix(), key, kid)
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	p := GoogleOIDCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"audience": "aud1"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}
func TestVerifyRS256AndParseAndVerify(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	kid := "kid1"
	tok := makeToken("aud", "sub", time.Now().Add(time.Hour).Unix(), key, kid)
	parts := strings.Split(tok, ".")
	if !verifyRS256(parts, &key.PublicKey) {
		t.Fatal("verifyRS256 failed")
	}
	bad := []string{parts[0], parts[1], parts[2] + "bad"}
	if verifyRS256(bad, &key.PublicKey) {
		t.Fatal("verifyRS256 should fail")
	}
	keyCache.mu.Lock()
	keyCache.keys = map[string]*rsa.PublicKey{kid: &key.PublicKey}
	keyCache.expiry = time.Now().Add(time.Hour)
	keyCache.mu.Unlock()
	claims, ok := parseAndVerify(tok)
	if !ok || claims["sub"] != "sub" {
		t.Fatalf("unexpected claims %v", claims)
	}
	if _, ok := parseAndVerify(parts[0] + "." + parts[1] + ".bad"); ok {
		t.Fatal("expected parseAndVerify failure")
	}
}

func TestFetchKeysCacheControl(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	kid := "kc"
	jwks := jwksForKey(&key.PublicKey, kid)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
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
	keyCache.keys = nil
	keyCache.mu.Unlock()
	defer func() {
		keyCache.mu.Lock()
		keyCache.keys = nil
		keyCache.mu.Unlock()
	}()

	if err := fetchKeys(); err != nil {
		t.Fatal(err)
	}
	keyCache.mu.RLock()
	_, ok := keyCache.keys[kid]
	exp := keyCache.expiry
	keyCache.mu.RUnlock()
	if !ok {
		t.Fatalf("expected key %s to be cached", kid)
	}
	if exp.Before(time.Now().Add(55*time.Second)) || exp.After(time.Now().Add(65*time.Second)) {
		t.Fatalf("unexpected expiry %v", exp)
	}
}

func TestFetchKeysCacheControlInvalid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	kid := "kbad"
	jwks := jwksForKey(&key.PublicKey, kid)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=nope")
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
	keyCache.keys = nil
	keyCache.mu.Unlock()
	defer func() {
		keyCache.mu.Lock()
		keyCache.keys = nil
		keyCache.mu.Unlock()
	}()

	now := time.Now()
	if err := fetchKeys(); err != nil {
		t.Fatal(err)
	}
	keyCache.mu.RLock()
	_, ok := keyCache.keys[kid]
	exp := keyCache.expiry
	keyCache.mu.RUnlock()
	if !ok {
		t.Fatalf("expected key %s to be cached", kid)
	}
	if exp.Before(now.Add(59*time.Minute)) || exp.After(now.Add(time.Hour+time.Minute)) {
		t.Fatalf("unexpected expiry %v", exp)
	}
}

func TestParseAndVerifyBadHeaders(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"k"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"a"}`))
	tok := header + "." + payload + ".sig"
	if _, ok := parseAndVerify(tok); ok {
		t.Fatal("expected failure for bad alg")
	}

	header2 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	tok2 := header2 + "." + payload + ".sig"
	keyCache.mu.Lock()
	oldKeys := keyCache.keys
	oldExp := keyCache.expiry
	keyCache.keys = map[string]*rsa.PublicKey{"k": nil}
	keyCache.expiry = time.Now().Add(time.Hour)
	keyCache.mu.Unlock()
	defer func() {
		keyCache.mu.Lock()
		keyCache.keys = oldKeys
		keyCache.expiry = oldExp
		keyCache.mu.Unlock()
	}()
	if _, ok := parseAndVerify(tok2); ok {
		t.Fatal("expected failure for missing kid")
	}

	header3 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"missing"}`))
	tok3 := header3 + "." + payload + ".sig"
	if _, ok := parseAndVerify(tok3); ok {
		t.Fatal("expected failure for unknown kid")
	}
}

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

func TestFetchKeysExpiresHeader2(t *testing.T) {
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

func TestGoogleOIDCParamMethods(t *testing.T) {
	p := GoogleOIDC{}
	if got := p.RequiredParams(); len(got) != 1 || got[0] != "audience" {
		t.Fatalf("unexpected required params %v", got)
	}
	if got := p.OptionalParams(); len(got) != 2 || got[0] != "header" || got[1] != "prefix" {
		t.Fatalf("unexpected optional params %v", got)
	}
	a := GoogleOIDCAuth{}
	if got := a.RequiredParams(); len(got) != 1 || got[0] != "audience" {
		t.Fatalf("unexpected required params %v", got)
	}
	if got := a.OptionalParams(); len(got) != 2 || got[0] != "header" || got[1] != "prefix" {
		t.Fatalf("unexpected optional params %v", got)
	}
}

func TestFetchTokenError(t *testing.T) {
	oldClient := HTTPClient
	HTTPClient = &http.Client{Transport: &failTransport{}}
	defer func() { HTTPClient = oldClient }()
	MetadataHost = "http://example.com"
	if _, _, err := fetchToken("aud"); err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifyRS256DecodeError(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	parts := []string{"a", "b", "!!"}
	if verifyRS256(parts, &key.PublicKey) {
		t.Fatal("expected failure")
	}
}

func TestGoogleOIDCAddAuthWrongConfigType(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := GoogleOIDC{}
	p.AddAuth(context.Background(), r, 5)
	if val := r.Header.Get("Authorization"); val != "" {
		t.Fatalf("expected no header set, got %s", val)
	}
}

func TestGetKeyFetchError(t *testing.T) {
	oldClient := HTTPClient
	HTTPClient = &http.Client{Transport: &failTransport{}}
	defer func() { HTTPClient = oldClient }()
	oldURL := CertsURL
	CertsURL = "http://example.com"
	defer func() { CertsURL = oldURL }()
	keyCache.mu.Lock()
	keyCache.keys = nil
	keyCache.expiry = time.Time{}
	keyCache.mu.Unlock()
	if _, err := getKey("missing"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseTokenBranches(t *testing.T) {
	if _, _, _, ok := parseToken("a.b"); ok {
		t.Fatal("expected parts error")
	}
	badH := base64.RawURLEncoding.EncodeToString([]byte("{"))
	if _, _, _, ok := parseToken(badH + ".b.c"); ok {
		t.Fatal("expected header unmarshal fail")
	}
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	if _, _, _, ok := parseToken(h + ".??.sig"); ok {
		t.Fatal("expected payload decode fail")
	}
	badP := base64.RawURLEncoding.EncodeToString([]byte("{"))
	if _, _, _, ok := parseToken(h + "." + badP + ".sig"); ok {
		t.Fatal("expected payload unmarshal fail")
	}
}

func TestFetchKeysInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "notjson")
	}))
	defer ts.Close()
	oldURL := CertsURL
	CertsURL = ts.URL
	defer func() { CertsURL = oldURL }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()
	if err := fetchKeys(); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseAndVerifyGetKeyError(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	tok := makeToken("a", "u", time.Now().Add(time.Hour).Unix(), key, "kid")
	keyCache.mu.Lock()
	keyCache.keys = nil
	keyCache.expiry = time.Now().Add(-time.Hour)
	keyCache.mu.Unlock()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"keys":[]}`)
	}))
	defer ts.Close()
	oldURL := CertsURL
	CertsURL = ts.URL
	defer func() { CertsURL = oldURL }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()
	if _, ok := parseAndVerify(tok); ok {
		t.Fatal("expected failure")
	}
}

func TestGoogleOIDCAuthenticateInvalidParams(t *testing.T) {
	r := &http.Request{}
	g := GoogleOIDCAuth{}
	if g.Authenticate(context.Background(), r, struct{}{}) {
		t.Fatal("expected failure")
	}
}

func TestGoogleOIDCIdentifyWrongParams(t *testing.T) {
	r := &http.Request{}
	g := GoogleOIDCAuth{}
	if id, ok := g.Identify(r, 5); ok || id != "" {
		t.Fatalf("unexpected id %s", id)
	}
}

func TestGoogleOIDCIdentifyPrefixMismatch(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"Token abc"}}}
	g := GoogleOIDCAuth{}
	cfg, _ := g.ParseParams(map[string]interface{}{"audience": "a"})
	if id, ok := g.Identify(r, cfg); ok || id != "" {
		t.Fatalf("expected prefix mismatch failure")
	}
}

func TestParseExpiryValues(t *testing.T) {
	if d := parseExpiry("bad"); time.Until(d) <= 0 {
		t.Fatalf("unexpected expiry %v", d)
	}
	part := base64.RawURLEncoding.EncodeToString([]byte("{"))
	if d := parseExpiry("h." + part); time.Until(d) <= 0 {
		t.Fatalf("unexpected expiry %v", d)
	}
	expTime := time.Now().Add(time.Hour).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, expTime)))
	d := parseExpiry("h." + payload)
	if d.Unix() != expTime {
		t.Fatalf("unexpected expiry %v", d)
	}
}

func TestParseAndVerifyBadToken(t *testing.T) {
	if _, ok := parseAndVerify("abc"); ok {
		t.Fatal("expected failure for malformed token")
	}
}

func TestFetchTokenBadURL(t *testing.T) {
	oldHost := MetadataHost
	MetadataHost = "://"
	defer func() { MetadataHost = oldHost }()
	if _, _, err := fetchToken("aud"); err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchKeysInvalidKeyData(t *testing.T) {
	jwks := `{"keys":[{"kty":"RSA","kid":"bad","alg":"RS256","n":"!!","e":"!!"}]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, jwks) }))
	defer ts.Close()
	oldURL := CertsURL
	CertsURL = ts.URL
	defer func() { CertsURL = oldURL }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()
	keyCache.mu.Lock()
	keyCache.keys = nil
	keyCache.expiry = time.Time{}
	keyCache.mu.Unlock()
	if err := fetchKeys(); err != nil {
		t.Fatal(err)
	}
	keyCache.mu.RLock()
	_, ok := keyCache.keys["bad"]
	keyCache.mu.RUnlock()
	if ok {
		t.Fatal("invalid key should not be cached")
	}
}
func TestGoogleOIDCStripAuthInvalidParams(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"tok"}}}
	g := GoogleOIDCAuth{}
	g.StripAuth(r, nil)
	if r.Header.Get("Authorization") == "" {
		t.Fatal("header should remain when params nil")
	}
	g.StripAuth(r, struct{}{})
	if r.Header.Get("Authorization") == "" {
		t.Fatal("header should remain when params wrong type")
	}
}

func TestGoogleOIDCIdentifyParseFail(t *testing.T) {
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer bad"}}}
	g := GoogleOIDCAuth{}
	cfg, _ := g.ParseParams(map[string]interface{}{"audience": "a"})
	if id, ok := g.Identify(r, cfg); ok || id != "" {
		t.Fatalf("expected failure, got %s", id)
	}
}

func TestGoogleOIDCAuthenticateExpired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	kid := "ex"
	jwks := jwksForKey(&key.PublicKey, kid)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, jwks) }))
	defer ts.Close()
	oldURL := CertsURL
	CertsURL = ts.URL
	defer func() { CertsURL = oldURL }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()
	tok := makeToken("aud", "u", time.Now().Add(-time.Hour).Unix(), key, kid)
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	g := GoogleOIDCAuth{}
	cfg, _ := g.ParseParams(map[string]interface{}{"audience": "aud"})
	if g.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected failure for expired token")
	}
}

type bodyErrTransport struct{}

func (bodyErrTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(errReadCloser{})}, nil
}

func TestFetchTokenReadError(t *testing.T) {
	oldClient := HTTPClient
	HTTPClient = &http.Client{Transport: bodyErrTransport{}}
	defer func() { HTTPClient = oldClient }()
	MetadataHost = "http://example.com"
	if _, _, err := fetchToken("aud"); err == nil {
		t.Fatal("expected read error")
	}
}

func TestFetchKeysBadExponent(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	jwks := fmt.Sprintf(`{"keys":[{"kid":"bad","alg":"RS256","n":"%s","e":"!!"}]}`, n)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, jwks) }))
	defer ts.Close()
	oldURL := CertsURL
	CertsURL = ts.URL
	defer func() { CertsURL = oldURL }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()
	keyCache.mu.Lock()
	keyCache.keys = nil
	keyCache.expiry = time.Time{}
	keyCache.mu.Unlock()
	if err := fetchKeys(); err != nil {
		t.Fatal(err)
	}
	keyCache.mu.RLock()
	_, ok := keyCache.keys["bad"]
	keyCache.mu.RUnlock()
	if ok {
		t.Fatal("bad key should not be cached")
	}
}

type fetchErrTransport struct{}

func (fetchErrTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: errReadCloser{}}, nil
}

func TestFetchKeysBodyError(t *testing.T) {
	oldClient := HTTPClient
	HTTPClient = &http.Client{Transport: fetchErrTransport{}}
	defer func() { HTTPClient = oldClient }()
	oldURL := CertsURL
	CertsURL = "http://example.com"
	defer func() { CertsURL = oldURL }()
	keyCache.mu.Lock()
	keyCache.keys = nil
	keyCache.expiry = time.Time{}
	keyCache.mu.Unlock()
	if err := fetchKeys(); err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchKeysExpiresHeader(t *testing.T) {
	exp := time.Now().Add(2 * time.Hour).UTC().Format(http.TimeFormat)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Expires", exp)
		fmt.Fprint(w, `{"keys":[]}`)
	}))
	defer ts.Close()
	oldURL := CertsURL
	CertsURL = ts.URL
	defer func() { CertsURL = oldURL }()
	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()
	keyCache.mu.Lock()
	keyCache.keys = nil
	keyCache.expiry = time.Time{}
	keyCache.mu.Unlock()
	if err := fetchKeys(); err != nil {
		t.Fatal(err)
	}
	keyCache.mu.RLock()
	expTime := keyCache.expiry
	keyCache.mu.RUnlock()
	if expTime.Before(time.Now().Add(119*time.Minute)) || expTime.After(time.Now().Add(121*time.Minute)) {
		t.Fatalf("unexpected expiry %v", expTime)
	}
}
func TestGoogleOIDCAuthenticateParseFail(t *testing.T) {
	g := GoogleOIDCAuth{}
	cfg, _ := g.ParseParams(map[string]interface{}{"audience": "a"})
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer bad"}}}
	if g.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected failure for bad token")
	}
}
