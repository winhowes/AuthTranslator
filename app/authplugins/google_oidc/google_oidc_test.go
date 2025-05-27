package googleoidc

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/winhowes/AuthTransformer/app/secrets/plugins"
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

	p := GoogleOIDC{}
	cfg, err := p.ParseParams(map[string]interface{}{"audience": "testaud"})
	if err != nil {
		t.Fatal(err)
	}

	r := &http.Request{Header: http.Header{}}
	p.AddAuth(r, cfg)
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

	p := GoogleOIDC{}
	cfg, err := p.ParseParams(map[string]interface{}{"audience": "aud"})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{}}
	p.AddAuth(r, cfg)
	if got := r.Header.Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("unexpected header %s", got)
	}
}

func makeToken(aud, sub string, exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := fmt.Sprintf(`{"aud":"%s","sub":"%s","exp":%d}`, aud, sub, exp)
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return header + "." + body + "."
}

func TestGoogleOIDCIncomingAuth(t *testing.T) {
	tok := makeToken("aud1", "user1", time.Now().Add(time.Hour).Unix())
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	p := GoogleOIDCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"audience": "aud1"})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
	if id, ok := p.Identify(r, cfg); !ok || id != "user1" {
		t.Fatalf("unexpected identifier %s", id)
	}
}

func TestGoogleOIDCIncomingAuthFail(t *testing.T) {
	tok := makeToken("aud2", "u", time.Now().Add(-time.Hour).Unix())
	r := &http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tok}}}
	p := GoogleOIDCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"audience": "aud1"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}
