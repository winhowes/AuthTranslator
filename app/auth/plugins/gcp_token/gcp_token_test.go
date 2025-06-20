package gcptoken

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGCPTokenAddAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Errorf("missing metadata header")
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 10})
	}))
	defer ts.Close()

	oldHost := MetadataHost
	oldClient := HTTPClient
	MetadataHost = ts.URL
	HTTPClient = ts.Client()
	defer func() {
		MetadataHost = oldHost
		HTTPClient = oldClient
		setCachedToken("", time.Time{})
	}()

	p := GCPToken{}
	cfg, err := p.ParseParams(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("expected token header, got %s", got)
	}
}

func TestGCPTokenCache(t *testing.T) {
	setCachedToken("c", time.Now().Add(time.Hour))
	p := GCPToken{}
	cfg, _ := p.ParseParams(map[string]any{})
	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer c" {
		t.Fatalf("expected cached token, got %s", got)
	}
	setCachedToken("", time.Time{})
}

func TestGCPTokenRefreshEarly(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "new", "expires_in": 10})
	}))
	defer ts.Close()

	oldHost := MetadataHost
	oldClient := HTTPClient
	MetadataHost = ts.URL
	HTTPClient = ts.Client()
	defer func() {
		MetadataHost = oldHost
		HTTPClient = oldClient
		setCachedToken("", time.Time{})
	}()

	setCachedToken("old", time.Now().Add(30*time.Second))
	p := GCPToken{}
	cfg, _ := p.ParseParams(map[string]any{})
	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer new" {
		t.Fatalf("expected refreshed token, got %s", got)
	}
}

func TestGCPTokenParseDefaults(t *testing.T) {
	p := GCPToken{}
	cfg, err := p.ParseParams(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.(*gcpTokenParams)
	if c.Header != "Authorization" || c.Prefix != "Bearer " {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestGCPTokenWrongConfig(t *testing.T) {
	p := GCPToken{}
	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, struct{}{}); err == nil {
		t.Fatal("expected error")
	}
	if r.Header.Get("Authorization") != "" {
		t.Fatalf("expected no header")
	}
}
