package plugins

import (
	"context"
	"fmt"
	"io"
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

type errorRoundTripper struct{}

func (errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("network error")
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

func TestVaultLoadBadAddr(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://[::1")
	t.Setenv("VAULT_TOKEN", "tok")

	p := vaultPlugin{}
	if _, err := p.Load(context.Background(), "secret/data/foo"); err == nil {
		t.Fatal("expected url parse error")
	}
}

func TestVaultLoadNetworkError(t *testing.T) {
	old := HTTPClient
	HTTPClient = &http.Client{Transport: errorRoundTripper{}}
	defer func() { HTTPClient = old }()

	t.Setenv("VAULT_ADDR", "http://vault")
	t.Setenv("VAULT_TOKEN", "tok")

	p := vaultPlugin{}
	if _, err := p.Load(context.Background(), "secret/data/foo"); err == nil {
		t.Fatal("expected network error")
	}
}

func TestVaultLoadRequestError(t *testing.T) {
	oldReq := newRequest
	newRequest = func(string, string, io.Reader) (*http.Request, error) { return nil, fmt.Errorf("bad") }
	defer func() { newRequest = oldReq }()

	t.Setenv("VAULT_ADDR", "http://vault")
	t.Setenv("VAULT_TOKEN", "tok")

	p := vaultPlugin{}
	if _, err := p.Load(context.Background(), "secret/data/foo"); err == nil {
		t.Fatal("expected request error")
	}
}

func TestVaultLoadValueField(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"value":"secret"}}`)
	}))
	defer ts.Close()
	restore := setVaultTestClient(ts)
	defer restore()

	t.Setenv("VAULT_ADDR", "http://vault")
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
