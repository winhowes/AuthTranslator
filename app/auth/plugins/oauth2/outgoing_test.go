package oauth2

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/winhowes/AuthTranslator/app/secrets"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func resetCache() {
	tokenCache.Lock()
	tokenCache.m = make(map[string]cachedToken)
	tokenCache.refreshLocks = make(map[string]*sync.Mutex)
	tokenCache.Unlock()
	secrets.ClearCache()
}

func withTestClient(t *testing.T, client *http.Client) {
	t.Helper()
	oldClient := HTTPClient
	HTTPClient = client
	t.Cleanup(func() {
		HTTPClient = oldClient
		resetCache()
	})
}

func TestOAuth2RefreshTokenAddAuth(t *testing.T) {
	resetCache()
	t.Setenv("CLIENT_SECRET", "secret")
	t.Setenv("REFRESH_TOKEN", "refresh-1")

	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Fatalf("unexpected content type %q", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertForm(t, r, "grant_type", "refresh_token")
		assertForm(t, r, "client_id", "client")
		assertForm(t, r, "client_secret", "secret")
		assertForm(t, r, "refresh_token", "refresh-1")
		assertForm(t, r, "scope", "read write")
		assertForm(t, r, "audience", "https://api.example.com")
		assertForm(t, r, "resource", "https://resource.example.com")
		fmt.Fprint(w, `{"access_token":"access-1","expires_in":3600,"refresh_token":"refresh-2"}`)
	}))
	defer ts.Close()
	withTestClient(t, ts.Client())

	p := OAuth2{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"token_url":     ts.URL,
		"grant_type":    "refresh_token",
		"client_id":     "client",
		"client_secret": "env:CLIENT_SECRET",
		"refresh_token": "env:REFRESH_TOKEN",
		"scope":         "read write",
		"audience":      "https://api.example.com",
		"extra_params": map[string]string{
			"resource": "https://resource.example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer access-1" {
		t.Fatalf("unexpected auth header %q", got)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected one token request, got %d", got)
	}
}

func TestOAuth2CachesAccessToken(t *testing.T) {
	resetCache()
	t.Setenv("CLIENT_SECRET", "secret")

	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, `{"access_token":"cached","expires_in":3600}`)
	}))
	defer ts.Close()
	withTestClient(t, ts.Client())

	p := OAuth2{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"token_url":     ts.URL,
		"client_id":     "client",
		"client_secret": "env:CLIENT_SECRET",
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		r := &http.Request{Header: http.Header{}}
		if err := p.AddAuth(context.Background(), r, cfg); err != nil {
			t.Fatal(err)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer cached" {
			t.Fatalf("unexpected auth header %q", got)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected cached token to be reused, got %d token requests", got)
	}
}

func TestOAuth2RefreshesEarlyAndUsesRotatedRefreshToken(t *testing.T) {
	resetCache()
	t.Setenv("REFRESH_TOKEN", "refresh-1")

	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		switch atomic.AddInt32(&hits, 1) {
		case 1:
			assertForm(t, r, "refresh_token", "refresh-1")
			fmt.Fprint(w, `{"access_token":"old","expires_in":30,"refresh_token":"refresh-2"}`)
		case 2:
			assertForm(t, r, "refresh_token", "refresh-2")
			fmt.Fprint(w, `{"access_token":"new","expires_in":3600}`)
		default:
			t.Fatalf("unexpected token request %d", hits)
		}
	}))
	defer ts.Close()
	withTestClient(t, ts.Client())

	p := OAuth2{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"token_url":     ts.URL,
		"refresh_token": "env:REFRESH_TOKEN",
		"client_auth":   "none",
		"client_id":     "public-client",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed := cfg.(*oauth2Params)
	if parsed.GrantType != "refresh_token" {
		t.Fatalf("expected refresh_token default grant, got %q", parsed.GrantType)
	}

	r1 := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r1, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r1.Header.Get("Authorization"); got != "Bearer old" {
		t.Fatalf("unexpected first header %q", got)
	}

	r2 := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r2, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r2.Header.Get("Authorization"); got != "Bearer old" {
		t.Fatalf("short-lived token should be cached before refresh window, got %q", got)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected short-lived token to be cached, got %d token requests", got)
	}

	key := parsed.cacheKey()
	ct := getCachedToken(key)
	ct.refreshAt = time.Now().Add(-time.Second)
	setCachedToken(key, ct)

	r3 := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r3, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r3.Header.Get("Authorization"); got != "Bearer new" {
		t.Fatalf("unexpected refreshed header %q", got)
	}
}

func TestOAuth2SerializesConcurrentRefresh(t *testing.T) {
	resetCache()
	t.Setenv("REFRESH_TOKEN", "refresh-1")

	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		switch hit := atomic.AddInt32(&hits, 1); hit {
		case 1:
			if got := r.Form.Get("refresh_token"); got != "refresh-1" {
				t.Errorf("expected first refresh token %q, got %q", "refresh-1", got)
			}
			fmt.Fprint(w, `{"access_token":"old","expires_in":30,"refresh_token":"refresh-2"}`)
		case 2:
			if got := r.Form.Get("refresh_token"); got != "refresh-2" {
				t.Errorf("expected rotated refresh token %q, got %q", "refresh-2", got)
			}
			time.Sleep(25 * time.Millisecond)
			fmt.Fprint(w, `{"access_token":"new","expires_in":3600,"refresh_token":"refresh-3"}`)
		default:
			http.Error(w, fmt.Sprintf("unexpected concurrent refresh %d", hit), http.StatusBadRequest)
		}
	}))
	defer ts.Close()
	withTestClient(t, ts.Client())

	p := OAuth2{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"token_url":     ts.URL,
		"grant_type":    "refresh_token",
		"refresh_token": "env:REFRESH_TOKEN",
		"client_auth":   "none",
	})
	if err != nil {
		t.Fatal(err)
	}

	first := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), first, cfg); err != nil {
		t.Fatal(err)
	}
	if got := first.Header.Get("Authorization"); got != "Bearer old" {
		t.Fatalf("unexpected first token %q", got)
	}

	parsed := cfg.(*oauth2Params)
	key := parsed.cacheKey()
	ct := getCachedToken(key)
	ct.refreshAt = time.Now().Add(-time.Second)
	setCachedToken(key, ct)

	const workers = 8
	errs := make(chan error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r := &http.Request{Header: http.Header{}}
			if err := p.AddAuth(context.Background(), r, cfg); err != nil {
				errs <- err
				return
			}
			if got := r.Header.Get("Authorization"); got != "Bearer new" {
				errs <- fmt.Errorf("unexpected auth header %q", got)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected exactly two token endpoint calls, got %d", got)
	}
}

func TestOAuth2PreRefreshFailureUsesCachedToken(t *testing.T) {
	resetCache()
	t.Setenv("CLIENT_SECRET", "secret")

	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch atomic.AddInt32(&hits, 1) {
		case 1:
			fmt.Fprint(w, `{"access_token":"cached","expires_in":3600}`)
		default:
			http.Error(w, "temporary token endpoint failure", http.StatusServiceUnavailable)
		}
	}))
	defer ts.Close()
	withTestClient(t, ts.Client())

	p := OAuth2{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"token_url":     ts.URL,
		"client_id":     "client",
		"client_secret": "env:CLIENT_SECRET",
	})
	if err != nil {
		t.Fatal(err)
	}

	first := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), first, cfg); err != nil {
		t.Fatal(err)
	}
	if got := first.Header.Get("Authorization"); got != "Bearer cached" {
		t.Fatalf("unexpected first token %q", got)
	}

	parsed := cfg.(*oauth2Params)
	key := parsed.cacheKey()
	ct := getCachedToken(key)
	ct.refreshAt = time.Now().Add(-time.Second)
	setCachedToken(key, ct)

	fallback := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), fallback, cfg); err != nil {
		t.Fatalf("expected cached token fallback, got %v", err)
	}
	if got := fallback.Header.Get("Authorization"); got != "Bearer cached" {
		t.Fatalf("expected cached token fallback, got %q", got)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected failed pre-refresh attempt, got %d token requests", got)
	}

	ct = getCachedToken(key)
	ct.exp = time.Now().Add(-time.Second)
	ct.refreshAt = time.Now().Add(-time.Second)
	setCachedToken(key, ct)

	expired := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), expired, cfg); err == nil {
		t.Fatal("expected refresh error after cached token expiry")
	}
	if got := expired.Header.Get("Authorization"); got != "" {
		t.Fatalf("expected no header after expired-token refresh failure, got %q", got)
	}
}

func TestOAuth2ClientCredentialsBasicAuth(t *testing.T) {
	resetCache()
	t.Setenv("CLIENT_SECRET", "secret")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "client" || pass != "secret" {
			t.Fatalf("unexpected basic auth user=%q pass=%q ok=%v", user, pass, ok)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertForm(t, r, "grant_type", "client_credentials")
		if got := r.Form.Get("client_secret"); got != "" {
			t.Fatalf("client_secret should not be sent in body for basic auth, got %q", got)
		}
		fmt.Fprint(w, `{"access_token":"access-basic","expires_in":"3600"}`)
	}))
	defer ts.Close()
	withTestClient(t, ts.Client())

	p := OAuth2{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"token_url":     ts.URL,
		"grant_type":    "client_credentials",
		"client_id":     "client",
		"client_secret": "env:CLIENT_SECRET",
		"client_auth":   "basic",
		"header":        "X-Token",
		"prefix":        "Token ",
	})
	if err != nil {
		t.Fatal(err)
	}

	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("X-Token"); got != "Token access-basic" {
		t.Fatalf("unexpected auth header %q", got)
	}
}

func TestOAuth2ParseParamsValidation(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]interface{}
		want   string
	}{
		{
			name:   "missing token url",
			params: map[string]interface{}{},
			want:   "missing token_url",
		},
		{
			name: "invalid token url",
			params: map[string]interface{}{
				"token_url": "://bad",
			},
			want: "invalid token_url",
		},
		{
			name: "unsupported grant",
			params: map[string]interface{}{
				"token_url":  "https://auth.example.com/token",
				"grant_type": "password",
			},
			want: "unsupported grant_type",
		},
		{
			name: "missing refresh token",
			params: map[string]interface{}{
				"token_url":  "https://auth.example.com/token",
				"grant_type": "refresh_token",
			},
			want: "requires refresh_token",
		},
		{
			name: "client credentials missing secret",
			params: map[string]interface{}{
				"token_url": "https://auth.example.com/token",
				"client_id": "client",
			},
			want: "requires client_id and client_secret",
		},
		{
			name: "basic missing secret",
			params: map[string]interface{}{
				"token_url":     "https://auth.example.com/token",
				"grant_type":    "refresh_token",
				"refresh_token": "env:REFRESH_TOKEN",
				"client_id":     "client",
				"client_auth":   "basic",
			},
			want: "basic client_auth requires",
		},
		{
			name: "body secret without client id",
			params: map[string]interface{}{
				"token_url":     "https://auth.example.com/token",
				"grant_type":    "refresh_token",
				"refresh_token": "env:REFRESH_TOKEN",
				"client_secret": "env:CLIENT_SECRET",
			},
			want: "client_id is required",
		},
		{
			name: "none with secret",
			params: map[string]interface{}{
				"token_url":     "https://auth.example.com/token",
				"grant_type":    "refresh_token",
				"refresh_token": "env:REFRESH_TOKEN",
				"client_secret": "env:CLIENT_SECRET",
				"client_auth":   "none",
			},
			want: "client_secret cannot be used",
		},
		{
			name: "unsupported client auth",
			params: map[string]interface{}{
				"token_url":     "https://auth.example.com/token",
				"grant_type":    "refresh_token",
				"refresh_token": "env:REFRESH_TOKEN",
				"client_auth":   "signed",
			},
			want: "unsupported client_auth",
		},
		{
			name: "empty extra param key",
			params: map[string]interface{}{
				"token_url":     "https://auth.example.com/token",
				"client_id":     "client",
				"client_secret": "env:CLIENT_SECRET",
				"extra_params": map[string]string{
					" ": "x",
				},
			},
			want: "extra_params cannot contain empty keys",
		},
		{
			name: "extra param override",
			params: map[string]interface{}{
				"token_url":     "https://auth.example.com/token",
				"client_id":     "client",
				"client_secret": "env:CLIENT_SECRET",
				"extra_params": map[string]string{
					"grant_type": "refresh_token",
				},
			},
			want: "extra_params cannot override",
		},
		{
			name: "unknown field",
			params: map[string]interface{}{
				"token_url":     "https://auth.example.com/token",
				"client_id":     "client",
				"client_secret": "env:CLIENT_SECRET",
				"unknown":       true,
			},
			want: "unknown field",
		},
	}

	p := OAuth2{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := p.ParseParams(tt.params); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestOAuth2ParamLists(t *testing.T) {
	p := OAuth2{}
	if p.Name() != "oauth2" {
		t.Fatalf("unexpected name %q", p.Name())
	}
	if got := p.RequiredParams(); len(got) != 1 || got[0] != "token_url" {
		t.Fatalf("unexpected required params: %v", got)
	}
	opts := p.OptionalParams()
	for _, want := range []string{"grant_type", "client_id", "client_secret", "refresh_token", "scope", "audience", "client_auth", "header", "prefix", "extra_params"} {
		found := false
		for _, got := range opts {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing optional param %q in %v", want, opts)
		}
	}
}

func TestOAuth2AddAuthInvalidParams(t *testing.T) {
	p := OAuth2{}
	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, struct{}{}); err == nil {
		t.Fatal("expected invalid config error")
	}
}

func TestOAuth2SecretLoadErrors(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]interface{}
	}{
		{
			name: "client secret",
			params: map[string]interface{}{
				"token_url":     "https://auth.example.com/token",
				"client_id":     "client",
				"client_secret": "env:MISSING_CLIENT_SECRET",
			},
		},
		{
			name: "refresh token",
			params: map[string]interface{}{
				"token_url":     "https://auth.example.com/token",
				"grant_type":    "refresh_token",
				"refresh_token": "env:MISSING_REFRESH_TOKEN",
				"client_auth":   "none",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCache()
			p := OAuth2{}
			cfg, err := p.ParseParams(tt.params)
			if err != nil {
				t.Fatal(err)
			}
			r := &http.Request{Header: http.Header{}}
			if err := p.AddAuth(context.Background(), r, cfg); err == nil {
				t.Fatal("expected secret load error")
			}
			if got := r.Header.Get("Authorization"); got != "" {
				t.Fatalf("expected empty auth header, got %q", got)
			}
		})
	}
}

func TestOAuth2FetchTokenRequestBuildError(t *testing.T) {
	_, err := fetchToken(context.Background(), &oauth2Params{
		TokenURL:   "http://[::1",
		GrantType:  "refresh_token",
		ClientAuth: "none",
	}, "")
	if err == nil {
		t.Fatal("expected request construction error")
	}
}

func TestOAuth2FetchTokenTransportError(t *testing.T) {
	resetCache()
	oldClient := HTTPClient
	HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("boom")
	})}
	t.Cleanup(func() {
		HTTPClient = oldClient
		resetCache()
	})

	_, err := fetchToken(context.Background(), &oauth2Params{
		TokenURL:     "https://auth.example.com/token",
		GrantType:    "client_credentials",
		ClientID:     "client",
		ClientSecret: "env:CLIENT_SECRET",
		ClientAuth:   "body",
	}, "")
	if err == nil || !strings.Contains(err.Error(), "CLIENT_SECRET") {
		t.Fatalf("expected client secret load error before transport, got %v", err)
	}

	t.Setenv("CLIENT_SECRET", "secret")
	_, err = fetchToken(context.Background(), &oauth2Params{
		TokenURL:     "https://auth.example.com/token",
		GrantType:    "client_credentials",
		ClientID:     "client",
		ClientSecret: "env:CLIENT_SECRET",
		ClientAuth:   "body",
	}, "")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected transport error, got %v", err)
	}
}

func TestOAuth2TokenEndpointErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "bad status", status: http.StatusBadRequest, body: "bad token", want: "token request failed"},
		{name: "malformed json", status: http.StatusOK, body: "{broken", want: "invalid character"},
		{name: "empty token", status: http.StatusOK, body: `{"expires_in":3600}`, want: "empty access token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCache()
			t.Setenv("CLIENT_SECRET", "secret")
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			defer ts.Close()
			withTestClient(t, ts.Client())

			p := OAuth2{}
			cfg, err := p.ParseParams(map[string]interface{}{
				"token_url":     ts.URL,
				"client_id":     "client",
				"client_secret": "env:CLIENT_SECRET",
			})
			if err != nil {
				t.Fatal(err)
			}
			r := &http.Request{Header: http.Header{}}
			err = p.AddAuth(context.Background(), r, cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
			if got := r.Header.Get("Authorization"); got != "" {
				t.Fatalf("expected auth header to remain empty, got %q", got)
			}
		})
	}
}

func TestOAuth2SecretRefsAndDefaults(t *testing.T) {
	p := OAuth2{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"token_url":     "https://auth.example.com/token",
		"grant_type":    "refresh_token",
		"client_id":     "client",
		"client_secret": "env:CLIENT_SECRET",
		"refresh_token": "env:REFRESH_TOKEN",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed := cfg.(*oauth2Params)
	if parsed.Header != "Authorization" || parsed.Prefix != "Bearer " || parsed.ClientAuth != "body" {
		t.Fatalf("unexpected defaults: %+v", parsed)
	}
	refs := parsed.SecretRefs()
	if len(refs) != 2 || refs[0] != "env:CLIENT_SECRET" || refs[1] != "env:REFRESH_TOKEN" {
		t.Fatalf("unexpected refs: %v", refs)
	}
}

func TestOAuth2DefaultExpiry(t *testing.T) {
	if got := parseExpiresIn(nil); got != time.Minute {
		t.Fatalf("unexpected default expiry: %s", got)
	}
	if got := parseExpiresIn([]byte(`"120"`)); got != 120*time.Second {
		t.Fatalf("unexpected string expiry: %s", got)
	}
	if got := parseExpiresIn([]byte(`"nope"`)); got != time.Minute {
		t.Fatalf("unexpected fallback expiry: %s", got)
	}
	if got := parseExpiresIn([]byte(`{}`)); got != time.Minute {
		t.Fatalf("unexpected object fallback expiry: %s", got)
	}
}

func TestOAuth2TokenRefreshTime(t *testing.T) {
	now := time.Unix(1000, 0)

	if got := tokenRefreshTime(now, now.Add(-time.Second)); !got.Equal(now) {
		t.Fatalf("expired token should refresh now, got %s", got)
	}
	if got := tokenRefreshTime(now, now.Add(time.Nanosecond)); !got.Equal(now.Add(time.Nanosecond)) {
		t.Fatalf("sub-nanosecond skew should refresh at expiry, got %s", got)
	}
	if got := tokenRefreshTime(now, now.Add(30*time.Second)); !got.Equal(now.Add(27 * time.Second)) {
		t.Fatalf("short-lived token refreshAt should use proportional skew, got %s", got)
	}
	if got := tokenRefreshTime(now, now.Add(time.Hour)); !got.Equal(now.Add(59 * time.Minute)) {
		t.Fatalf("long-lived token refreshAt should cap skew, got %s", got)
	}
}

func TestOAuth2TokenNeedsRefreshWithComputedRefreshAt(t *testing.T) {
	if !tokenNeedsRefresh(cachedToken{}) {
		t.Fatal("empty cached token should refresh")
	}
	if tokenNeedsRefresh(cachedToken{accessToken: "tok", exp: time.Now().Add(30 * time.Second)}) {
		t.Fatal("short-lived token should not refresh immediately when refreshAt is absent")
	}
	if !tokenNeedsRefresh(cachedToken{accessToken: "tok", exp: time.Now().Add(-time.Second)}) {
		t.Fatal("expired token should refresh when refreshAt is absent")
	}
}

func TestOAuth2TokenUsable(t *testing.T) {
	now := time.Now()
	if tokenUsable(cachedToken{}, now) {
		t.Fatal("empty token should not be usable")
	}
	if tokenUsable(cachedToken{accessToken: "tok", exp: now}, now) {
		t.Fatal("token at expiry should not be usable")
	}
	if !tokenUsable(cachedToken{accessToken: "tok", exp: now.Add(time.Second)}, now) {
		t.Fatal("unexpired token should be usable")
	}
}

func TestOAuth2ClientAuthNoneIncludesClientID(t *testing.T) {
	resetCache()
	t.Setenv("REFRESH_TOKEN", "refresh")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertForm(t, r, "client_id", "public-client")
		assertForm(t, r, "refresh_token", "refresh")
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Fatalf("expected no client auth header, got %q", auth)
		}
		fmt.Fprint(w, `{"access_token":"public","expires_in":3600}`)
	}))
	defer ts.Close()
	withTestClient(t, ts.Client())

	p := OAuth2{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"token_url":     ts.URL,
		"grant_type":    "refresh_token",
		"refresh_token": "env:REFRESH_TOKEN",
		"client_auth":   "none",
		"client_id":     "public-client",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{}}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer public" {
		t.Fatalf("unexpected auth header %q", got)
	}
}

func TestOAuth2FetchTokenResponseCloseOnStatusError(t *testing.T) {
	resetCache()
	t.Setenv("CLIENT_SECRET", "secret")

	body := &closeRecorder{Reader: strings.NewReader("bad")}
	oldClient := HTTPClient
	HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Status:     "400 Bad Request",
			Body:       body,
		}, nil
	})}
	t.Cleanup(func() {
		HTTPClient = oldClient
		resetCache()
	})

	_, err := fetchToken(context.Background(), &oauth2Params{
		TokenURL:     "https://auth.example.com/token",
		GrantType:    "client_credentials",
		ClientID:     "client",
		ClientSecret: "env:CLIENT_SECRET",
		ClientAuth:   "body",
	}, "")
	if err == nil {
		t.Fatal("expected status error")
	}
	if !body.closed {
		t.Fatal("expected response body to be closed")
	}
}

func assertForm(t *testing.T, r *http.Request, key, want string) {
	t.Helper()
	if got := r.Form.Get(key); got != want {
		t.Fatalf("expected form %s=%q, got %q", key, want, got)
	}
}

type closeRecorder struct {
	io.Reader
	closed bool
}

func (c *closeRecorder) Close() error {
	c.closed = true
	return nil
}
