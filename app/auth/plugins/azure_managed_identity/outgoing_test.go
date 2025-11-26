package azuremanagedidentity

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func resetCache() {
	tokenCache.Lock()
	tokenCache.m = make(map[string]cachedToken)
	tokenCache.Unlock()
}

func TestAzureManagedIdentityAddAuth(t *testing.T) {
	resetCache()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			t.Errorf("missing metadata header")
		}
		if q := r.URL.Query().Get("resource"); q != "api://res" {
			t.Fatalf("unexpected resource %s", q)
		}
		fmt.Fprint(w, `{"access_token":"tok123","expires_in":"3600"}`)
	}))
	defer ts.Close()

	oldHost := MetadataHost
	MetadataHost = ts.URL
	defer func() { MetadataHost = oldHost }()

	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	p := AzureManagedIdentity{}
	cfg, err := p.ParseParams(map[string]interface{}{"resource": "api://res"})
	if err != nil {
		t.Fatal(err)
	}

	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer tok123" {
		t.Fatalf("unexpected header %s", got)
	}
}

func TestAzureManagedIdentityCustomHeaderAndPrefix(t *testing.T) {
	resetCache()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"tok","expires_in":120}`)
	}))
	defer ts.Close()

	oldHost := MetadataHost
	MetadataHost = ts.URL
	defer func() { MetadataHost = oldHost }()

	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	p := AzureManagedIdentity{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"resource":  "api://res",
		"header":    "X-Auth",
		"prefix":    "Token ",
		"client_id": "client1",
	})
	if err != nil {
		t.Fatal(err)
	}

	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("X-Auth"); got != "Token tok" {
		t.Fatalf("unexpected header %s", got)
	}
}

func TestAzureManagedIdentityAddAuthFailure(t *testing.T) {
	resetCache()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "bad")
	}))
	defer ts.Close()

	oldHost := MetadataHost
	MetadataHost = ts.URL
	defer func() { MetadataHost = oldHost }()

	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	p := AzureManagedIdentity{}
	cfg, err := p.ParseParams(map[string]interface{}{"resource": "api://fail"})
	if err != nil {
		t.Fatal(err)
	}

	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, cfg); err == nil {
		t.Fatal("expected error")
	}
	if got := r.Header.Get("Authorization"); got != "" {
		t.Fatalf("expected empty header, got %s", got)
	}
}

func TestAzureManagedIdentityCache(t *testing.T) {
	resetCache()

	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
	}))
	defer ts.Close()

	oldHost := MetadataHost
	MetadataHost = ts.URL
	defer func() { MetadataHost = oldHost }()

	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	p := AzureManagedIdentity{}
	cfg, err := p.ParseParams(map[string]interface{}{"resource": "api://res"})
	if err != nil {
		t.Fatal(err)
	}

	r1 := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r1, cfg); err != nil {
		t.Fatal(err)
	}
	r2 := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r2, cfg); err != nil {
		t.Fatal(err)
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected single fetch, got %d", got)
	}
}

func TestAzureManagedIdentityParseParamsMissingResource(t *testing.T) {
	resetCache()

	p := AzureManagedIdentity{}
	if _, err := p.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestAzureManagedIdentityAddAuthWrongParams(t *testing.T) {
	resetCache()

	p := AzureManagedIdentity{}
	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, 5); err == nil {
		t.Fatal("expected error")
	}
}

func TestAzureManagedIdentityUsesExpiresOn(t *testing.T) {
	resetCache()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expiresOn := time.Now().Add(2 * time.Hour).Unix()
		fmt.Fprintf(w, `{"access_token":"tok","expires_on":"%d"}`, expiresOn)
	}))
	defer ts.Close()

	oldHost := MetadataHost
	MetadataHost = ts.URL
	defer func() { MetadataHost = oldHost }()

	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	p := AzureManagedIdentity{}
	cfg, err := p.ParseParams(map[string]interface{}{"resource": "api://res"})
	if err != nil {
		t.Fatal(err)
	}

	// First call populates cache.
	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}

	tok, exp := getCachedToken("api://res|")
	if tok != "tok" {
		t.Fatalf("unexpected token %s", tok)
	}
	if time.Until(exp) < time.Hour {
		t.Fatalf("expected long-lived expiry, got %s", exp)
	}
}

func TestAzureManagedIdentityParamLists(t *testing.T) {
	p := AzureManagedIdentity{}
	if got := p.RequiredParams(); len(got) != 1 || got[0] != "resource" {
		t.Fatalf("unexpected required params: %v", got)
	}
	wantOpt := []string{"client_id", "header", "prefix"}
	if got := p.OptionalParams(); len(got) != len(wantOpt) {
		t.Fatalf("unexpected optional params length: %v", got)
	} else {
		for i, v := range wantOpt {
			if got[i] != v {
				t.Fatalf("unexpected optional param %q at %d", got[i], i)
			}
		}
	}
}

func TestAzureManagedIdentityParseParamsInvalidType(t *testing.T) {
	p := AzureManagedIdentity{}
	if _, err := p.ParseParams(map[string]interface{}{"resource": 5}); err == nil {
		t.Fatal("expected parse error for invalid type")
	}
}

func TestFetchTokenEmptyAccessToken(t *testing.T) {
	resetCache()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"expires_in": 60}`)
	}))
	defer ts.Close()

	oldHost := MetadataHost
	MetadataHost = ts.URL
	defer func() { MetadataHost = oldHost }()

	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	if _, _, err := fetchToken(context.Background(), "api://res", ""); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestParseExpiryDefault(t *testing.T) {
	now := time.Now()
	exp := parseExpiry("", "")
	if until := time.Until(exp); until < 50*time.Second || until > 70*time.Second {
		t.Fatalf("unexpected default expiry window: %s (now=%s exp=%s)", until, now, exp)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchTokenTransportError(t *testing.T) {
	oldClient := HTTPClient
	HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("boom")
	})}
	defer func() { HTTPClient = oldClient }()

	if _, _, err := fetchToken(context.Background(), "api://res", ""); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestFetchTokenDecodeError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{broken")
	}))
	defer ts.Close()

	oldHost := MetadataHost
	MetadataHost = ts.URL
	defer func() { MetadataHost = oldHost }()

	oldClient := HTTPClient
	HTTPClient = ts.Client()
	defer func() { HTTPClient = oldClient }()

	if _, _, err := fetchToken(context.Background(), "api://res", ""); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestFetchTokenBadURL(t *testing.T) {
	oldHost := MetadataHost
	MetadataHost = "://bad url"
	defer func() { MetadataHost = oldHost }()

	if _, _, err := fetchToken(context.Background(), "api://res", ""); err == nil {
		t.Fatal("expected url parse error")
	}
}
