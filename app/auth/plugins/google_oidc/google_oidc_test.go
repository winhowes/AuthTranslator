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
