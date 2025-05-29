package plugins

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type vaultRewriteTransport struct {
	rt     http.RoundTripper
	scheme string
	host   string
}

func (t *vaultRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = t.scheme
	req.URL.Host = t.host
	return t.rt.RoundTrip(req)
}

func setVaultTestClient(ts *httptest.Server) func() {
	oldDef := http.DefaultClient
	old := HTTPClient
	u, _ := url.Parse(ts.URL)
	c := &http.Client{Transport: &vaultRewriteTransport{rt: ts.Client().Transport, scheme: u.Scheme, host: u.Host}}
	http.DefaultClient = c
	HTTPClient = c
	return func() {
		http.DefaultClient = oldDef
		HTTPClient = old
	}
}

func TestVaultLoad(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok" {
			t.Errorf("missing auth header")
		}
		fmt.Fprint(w, `{"data":{"data":{"value":"secret"}}}`)
	}))
	defer ts.Close()
	restore := setVaultTestClient(ts)
	defer restore()

	t.Setenv("VAULT_ADDR", "https://vault.example.com")
	t.Setenv("VAULT_TOKEN", "tok")

	p := vaultPlugin{}
	got, err := p.Load(context.Background(), "secret/data/foo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "secret" {
		t.Fatalf("expected secret, got %s", got)
	}
}

func TestVaultLoadError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer ts.Close()
	restore := setVaultTestClient(ts)
	defer restore()

	t.Setenv("VAULT_ADDR", "https://vault.example.com")
	t.Setenv("VAULT_TOKEN", "tok")

	p := vaultPlugin{}
	if _, err := p.Load(context.Background(), "secret/data/foo"); err == nil {
		t.Fatal("expected error")
	}
}

func TestVaultLoadMissingConfig(t *testing.T) {
	p := vaultPlugin{}
	if _, err := p.Load(context.Background(), "secret/data/foo"); err == nil {
		t.Fatal("expected error when config missing")
	}
}

func TestVaultLoadDecodeError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "notjson")
	}))
	defer ts.Close()
	restore := setVaultTestClient(ts)
	defer restore()

	t.Setenv("VAULT_ADDR", "http://vault")
	t.Setenv("VAULT_TOKEN", "tok")

	p := vaultPlugin{}
	if _, err := p.Load(context.Background(), "secret/data/foo"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestVaultLoadValueMissing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"data":{}}}`)
	}))
	defer ts.Close()
	restore := setVaultTestClient(ts)
	defer restore()

	t.Setenv("VAULT_ADDR", "http://vault")
	t.Setenv("VAULT_TOKEN", "tok")

	p := vaultPlugin{}
	if _, err := p.Load(context.Background(), "secret/data/foo"); err == nil {
		t.Fatal("expected missing value error")
	}
}
