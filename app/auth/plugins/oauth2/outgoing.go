package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

const refreshSkew = time.Minute

// oauth2Params configures generic OAuth2 access-token acquisition for outgoing
// requests. client_secret and refresh_token are secret references, not raw values.
type oauth2Params struct {
	TokenURL     string            `json:"token_url"`
	GrantType    string            `json:"grant_type"`
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"client_secret"`
	RefreshToken string            `json:"refresh_token"`
	Scope        string            `json:"scope"`
	Audience     string            `json:"audience"`
	ClientAuth   string            `json:"client_auth"`
	Header       string            `json:"header"`
	Prefix       string            `json:"prefix"`
	ExtraParams  map[string]string `json:"extra_params"`
}

// OAuth2 obtains OAuth2 access tokens from a configurable token endpoint and
// attaches them to outgoing requests.
type OAuth2 struct{}

// HTTPClient performs token endpoint HTTP requests. It can be swapped in tests.
var HTTPClient = &http.Client{Timeout: 5 * time.Second}

type cachedToken struct {
	accessToken  string
	refreshToken string
	exp          time.Time
}

var tokenCache = struct {
	sync.Mutex
	m            map[string]cachedToken
	refreshLocks map[string]*sync.Mutex
}{m: make(map[string]cachedToken), refreshLocks: make(map[string]*sync.Mutex)}

type tokenResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
	RefreshToken string          `json:"refresh_token"`
}

func (o *OAuth2) Name() string { return "oauth2" }

func (o *OAuth2) RequiredParams() []string { return []string{"token_url"} }

func (o *OAuth2) OptionalParams() []string {
	return []string{
		"grant_type",
		"client_id",
		"client_secret",
		"refresh_token",
		"scope",
		"audience",
		"client_auth",
		"header",
		"prefix",
		"extra_params",
	}
}

func (o *OAuth2) ParseParams(m map[string]interface{}) (interface{}, error) {
	_, prefixSet := m["prefix"]

	p, err := authplugins.ParseParams[oauth2Params](m)
	if err != nil {
		return nil, err
	}
	if p.TokenURL == "" {
		return nil, fmt.Errorf("missing token_url")
	}
	u, err := url.Parse(p.TokenURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid token_url")
	}
	if p.GrantType == "" {
		if p.RefreshToken != "" {
			p.GrantType = "refresh_token"
		} else {
			p.GrantType = "client_credentials"
		}
	}
	if p.ClientAuth == "" {
		p.ClientAuth = "body"
	}
	if p.Header == "" {
		p.Header = "Authorization"
	}
	if !prefixSet {
		p.Prefix = "Bearer "
	}
	if err := validateOAuth2Params(p); err != nil {
		return nil, err
	}
	return p, nil
}

func validateOAuth2Params(p *oauth2Params) error {
	switch p.GrantType {
	case "client_credentials":
		if p.ClientID == "" || p.ClientSecret == "" {
			return fmt.Errorf("client_credentials grant requires client_id and client_secret")
		}
	case "refresh_token":
		if p.RefreshToken == "" {
			return fmt.Errorf("refresh_token grant requires refresh_token")
		}
	default:
		return fmt.Errorf("unsupported grant_type %q", p.GrantType)
	}

	switch p.ClientAuth {
	case "body":
		if p.ClientSecret != "" && p.ClientID == "" {
			return fmt.Errorf("client_id is required with client_secret")
		}
	case "basic":
		if p.ClientID == "" || p.ClientSecret == "" {
			return fmt.Errorf("basic client_auth requires client_id and client_secret")
		}
	case "none":
		if p.ClientSecret != "" {
			return fmt.Errorf("client_secret cannot be used with client_auth none")
		}
	default:
		return fmt.Errorf("unsupported client_auth %q", p.ClientAuth)
	}

	for k := range p.ExtraParams {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			return fmt.Errorf("extra_params cannot contain empty keys")
		}
		switch key {
		case "grant_type", "client_id", "client_secret", "refresh_token", "scope", "audience":
			return fmt.Errorf("extra_params cannot override %q", key)
		}
	}
	return nil
}

func (p *oauth2Params) SecretRefs() []string {
	var refs []string
	if p.ClientSecret != "" {
		refs = append(refs, p.ClientSecret)
	}
	if p.RefreshToken != "" {
		refs = append(refs, p.RefreshToken)
	}
	return refs
}

func (o *OAuth2) AddAuth(ctx context.Context, r *http.Request, params interface{}) error {
	cfg, ok := params.(*oauth2Params)
	if !ok {
		return fmt.Errorf("invalid config")
	}

	key := cfg.cacheKey()
	ct := getCachedToken(key)
	if tokenNeedsRefresh(ct) {
		refreshLock := getRefreshLock(key)
		refreshLock.Lock()
		defer refreshLock.Unlock()

		ct = getCachedToken(key)
		if !tokenNeedsRefresh(ct) {
			r.Header.Set(cfg.Header, cfg.Prefix+ct.accessToken)
			return nil
		}

		next, err := fetchToken(ctx, cfg, ct.refreshToken)
		if err != nil {
			return err
		}
		if next.refreshToken == "" {
			next.refreshToken = ct.refreshToken
		}
		setCachedToken(key, next)
		ct = next
	}

	r.Header.Set(cfg.Header, cfg.Prefix+ct.accessToken)
	return nil
}

func tokenNeedsRefresh(ct cachedToken) bool {
	return ct.accessToken == "" || time.Now().After(ct.exp.Add(-refreshSkew))
}

func fetchToken(ctx context.Context, cfg *oauth2Params, cachedRefreshToken string) (cachedToken, error) {
	form := url.Values{}
	form.Set("grant_type", cfg.GrantType)
	if cfg.Scope != "" {
		form.Set("scope", cfg.Scope)
	}
	if cfg.Audience != "" {
		form.Set("audience", cfg.Audience)
	}
	for k, v := range cfg.ExtraParams {
		form.Set(k, v)
	}

	clientSecret, err := loadSecretRef(ctx, cfg.ClientSecret)
	if err != nil {
		return cachedToken{}, err
	}

	if cfg.GrantType == "refresh_token" {
		refreshToken := cachedRefreshToken
		if refreshToken == "" {
			refreshToken, err = loadSecretRef(ctx, cfg.RefreshToken)
			if err != nil {
				return cachedToken{}, err
			}
		}
		form.Set("refresh_token", refreshToken)
	}

	switch cfg.ClientAuth {
	case "body":
		if cfg.ClientID != "" {
			form.Set("client_id", cfg.ClientID)
		}
		if cfg.ClientSecret != "" {
			form.Set("client_secret", clientSecret)
		}
	case "basic":
		// Added below after the request is built.
	case "none":
		if cfg.ClientID != "" {
			form.Set("client_id", cfg.ClientID)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return cachedToken{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cfg.ClientAuth == "basic" {
		req.SetBasicAuth(cfg.ClientID, clientSecret)
	}

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return cachedToken{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return cachedToken{}, fmt.Errorf("token request failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return cachedToken{}, err
	}
	if tr.AccessToken == "" {
		return cachedToken{}, fmt.Errorf("empty access token")
	}

	return cachedToken{
		accessToken:  tr.AccessToken,
		refreshToken: tr.RefreshToken,
		exp:          time.Now().Add(parseExpiresIn(tr.ExpiresIn)),
	}, nil
}

func loadSecretRef(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", nil
	}
	return secrets.LoadSecret(ctx, ref)
}

func parseExpiresIn(raw json.RawMessage) time.Duration {
	if len(raw) == 0 {
		return time.Minute
	}
	var seconds float64
	if err := json.Unmarshal(raw, &seconds); err == nil && seconds > 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if parsed, err := strconv.ParseFloat(text, 64); err == nil && parsed > 0 {
			return time.Duration(parsed * float64(time.Second))
		}
	}
	return time.Minute
}

func (p *oauth2Params) cacheKey() string {
	parts := []string{
		p.TokenURL,
		p.GrantType,
		p.ClientID,
		p.ClientSecret,
		p.RefreshToken,
		p.Scope,
		p.Audience,
		p.ClientAuth,
	}
	keys := make([]string, 0, len(p.ExtraParams))
	for k := range p.ExtraParams {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+p.ExtraParams[k])
	}
	return strings.Join(parts, "\x00")
}

func getCachedToken(key string) cachedToken {
	tokenCache.Lock()
	defer tokenCache.Unlock()
	return tokenCache.m[key]
}

func setCachedToken(key string, tok cachedToken) {
	tokenCache.Lock()
	tokenCache.m[key] = tok
	tokenCache.Unlock()
}

func getRefreshLock(key string) *sync.Mutex {
	tokenCache.Lock()
	defer tokenCache.Unlock()
	refreshLock := tokenCache.refreshLocks[key]
	if refreshLock == nil {
		refreshLock = &sync.Mutex{}
		tokenCache.refreshLocks[key] = refreshLock
	}
	return refreshLock
}

func init() { authplugins.RegisterOutgoing(&OAuth2{}) }
