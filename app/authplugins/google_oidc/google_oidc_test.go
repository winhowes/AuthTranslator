package googleoidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

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
