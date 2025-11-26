package azureoidc

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

func TestAzureOIDCAddAuth(t *testing.T) {
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

	p := AzureOIDC{}
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

func TestAzureOIDCCustomHeaderAndPrefix(t *testing.T) {
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

	p := AzureOIDC{}
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

func TestAzureOIDCAddAuthFailure(t *testing.T) {
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

	p := AzureOIDC{}
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

func TestAzureOIDCCache(t *testing.T) {
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

	p := AzureOIDC{}
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

func TestAzureOIDCParseParamsMissingResource(t *testing.T) {
	resetCache()

	p := AzureOIDC{}
	if _, err := p.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestAzureOIDCAddAuthWrongParams(t *testing.T) {
	resetCache()

	p := AzureOIDC{}
	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, 5); err == nil {
		t.Fatal("expected error")
	}
}

func TestAzureOIDCUsesExpiresOn(t *testing.T) {
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

	p := AzureOIDC{}
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
