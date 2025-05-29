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

type azureRewriteTransport struct {
	rt     http.RoundTripper
	scheme string
	host   string
}

type errorRoundTripper struct{}

func (errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("network error")
}

type tokenThenError struct{ done bool }

func (t *tokenThenError) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.done {
		t.done = true
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Type", "application/json")
		fmt.Fprint(rec, `{"access_token":"tok"}`)
		return rec.Result(), nil
	}
	return nil, fmt.Errorf("net err")
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

func TestAzureKMSSecretStatusError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok"}`)
			return
		}
		http.Error(w, "bad", http.StatusInternalServerError)
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

func TestAzureKMSMissingCreds(t *testing.T) {
	p := azureKMSPlugin{}
	if _, err := p.Load(context.Background(), "https://vault.example.com/secrets/foo"); err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

func TestAzureKMSTokenDecodeError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.Write([]byte("badjson"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()
	restore := setAzureTestClient(ts)
	defer restore()

	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "id")
	t.Setenv("AZURE_CLIENT_SECRET", "sec")

	p := azureKMSPlugin{}
	if _, err := p.Load(context.Background(), "https://vault.example.com/secrets/foo"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestAzureKMSSecretDecodeError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/tenant/oauth2/v2.0/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok"}`)
		case r.Method == "GET" && r.URL.Path == "/secrets/foo":
			w.Write([]byte("notjson"))
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
	if _, err := p.Load(context.Background(), "https://vault.example.com/secrets/foo"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestAzureKMSTokenRequestFailure(t *testing.T) {
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

func TestAzureKMSBadURL(t *testing.T) {
	var rt tokenThenError
	c := &http.Client{Transport: &rt}
	old := HTTPClient
	HTTPClient = c
	defer func() { HTTPClient = old }()

	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "id")
	t.Setenv("AZURE_CLIENT_SECRET", "sec")

	p := azureKMSPlugin{}
	if _, err := p.Load(context.Background(), "http://[::1"); err == nil {
		t.Fatal("expected error for bad url")
	}
}

func TestAzureKMSTokenRequestNetworkError(t *testing.T) {
	old := HTTPClient
	HTTPClient = &http.Client{Transport: errorRoundTripper{}}
	defer func() { HTTPClient = old }()

	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "id")
	t.Setenv("AZURE_CLIENT_SECRET", "sec")

	p := azureKMSPlugin{}
	if _, err := p.Load(context.Background(), "https://vault.example.com/secrets/foo"); err == nil {
		t.Fatal("expected network error")
	}
}

func TestAzureKMSSecretNetworkError(t *testing.T) {
	var rt tokenThenError
	c := &http.Client{Transport: &rt}
	old := HTTPClient
	HTTPClient = c
	defer func() { HTTPClient = old }()

	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "id")
	t.Setenv("AZURE_CLIENT_SECRET", "sec")

	p := azureKMSPlugin{}
	if _, err := p.Load(context.Background(), "https://vault.example.com/secrets/foo"); err == nil {
		t.Fatal("expected network error")
	}
}

func TestAzureKMSTokenRequestBadNewRequest(t *testing.T) {
	oldReq := newRequest
	newRequest = func(string, string, io.Reader) (*http.Request, error) { return nil, fmt.Errorf("bad req") }
	defer func() { newRequest = oldReq }()

	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "id")
	t.Setenv("AZURE_CLIENT_SECRET", "sec")

	p := azureKMSPlugin{}
	if _, err := p.Load(context.Background(), "https://vault.example.com/secrets/foo"); err == nil {
		t.Fatal("expected request error")
	}
}
