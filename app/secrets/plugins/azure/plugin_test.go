package plugins

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type azureRewriteTransport struct {
	rt     http.RoundTripper
	scheme string
	host   string
}

func (t *azureRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = t.scheme
	req.URL.Host = t.host
	return t.rt.RoundTrip(req)
}

func setAzureTestClient(ts *httptest.Server) func() {
	oldDef := http.DefaultClient
	old := HTTPClient
	u, _ := url.Parse(ts.URL)
	c := &http.Client{Transport: &azureRewriteTransport{rt: ts.Client().Transport, scheme: u.Scheme, host: u.Host}}
	http.DefaultClient = c
	HTTPClient = c
	return func() {
		http.DefaultClient = oldDef
		HTTPClient = old
	}
}

func TestAzureKMSLoad(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/tenant/oauth2/v2.0/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok"}`)
		case r.Method == "GET" && r.URL.Path == "/secrets/foo":
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("missing auth header")
			}
			if r.URL.Query().Get("api-version") != "7.2" {
				t.Errorf("wrong api version %s", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"value":"secret"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	restore := setAzureTestClient(ts)
	defer restore()

	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "id")
	t.Setenv("AZURE_CLIENT_SECRET", "sec")

	p := azureKMSPlugin{}
	got, err := p.Load(context.Background(), "https://vault.example.com/secrets/foo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "secret" {
		t.Fatalf("expected secret, got %s", got)
	}
}

func TestAzureKMSLoadError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer ts.Close()
	restore := setAzureTestClient(ts)
	defer restore()

	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "id")
	t.Setenv("AZURE_CLIENT_SECRET", "sec")

	p := azureKMSPlugin{}
	if _, err := p.Load(context.Background(), "https://vault.example.com/secrets/foo"); err == nil {
		t.Fatal("expected error")
	}
}
