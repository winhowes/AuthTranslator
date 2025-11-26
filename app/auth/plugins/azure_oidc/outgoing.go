package azureoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
)

// azureOIDCParams configures the Azure OIDC plugin.
type azureOIDCParams struct {
	Resource string `json:"resource"`
	ClientID string `json:"client_id"`
	Header   string `json:"header"`
	Prefix   string `json:"prefix"`
}

// AzureOIDC obtains an access token from the Azure Instance Metadata Service and
// attaches it to outgoing requests.
type AzureOIDC struct{}

// MetadataHost is the base URL for the Azure metadata service. It can be
// overridden in tests.
var MetadataHost = "http://169.254.169.254"

// HTTPClient performs metadata HTTP requests. It can be swapped in tests.
var HTTPClient = &http.Client{Timeout: 5 * time.Second}

var tokenCache = struct {
	sync.Mutex
	m map[string]cachedToken
}{m: make(map[string]cachedToken)}

type cachedToken struct {
	token string
	exp   time.Time
}

func (a *AzureOIDC) Name() string { return "azure_oidc" }

func (a *AzureOIDC) RequiredParams() []string { return []string{"resource"} }

func (a *AzureOIDC) OptionalParams() []string { return []string{"client_id", "header", "prefix"} }

func (a *AzureOIDC) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[azureOIDCParams](m)
	if err != nil {
		return nil, err
	}
	if p.Resource == "" {
		return nil, fmt.Errorf("missing resource")
	}
	if p.Header == "" {
		p.Header = "Authorization"
	}
	if p.Prefix == "" {
		p.Prefix = "Bearer "
	}
	return p, nil
}

func (a *AzureOIDC) AddAuth(ctx context.Context, r *http.Request, params interface{}) error {
	cfg, ok := params.(*azureOIDCParams)
	if !ok {
		return fmt.Errorf("invalid config")
	}
	cacheKey := cfg.Resource + "|" + cfg.ClientID
	tok, exp := getCachedToken(cacheKey)
	if tok == "" || time.Now().After(exp.Add(-1*time.Minute)) {
		var err error
		tok, exp, err = fetchToken(ctx, cfg.Resource, cfg.ClientID)
		if err != nil {
			return err
		}
		setCachedToken(cacheKey, tok, exp)
	}
	r.Header.Set(cfg.Header, cfg.Prefix+tok)
	return nil
}

func fetchToken(ctx context.Context, resource, clientID string) (string, time.Time, error) {
	q := url.Values{}
	q.Set("resource", resource)
	q.Set("api-version", "2018-02-01")
	if clientID != "" {
		q.Set("client_id", clientID)
	}

	metaURL := fmt.Sprintf("%s/metadata/identity/oauth2/token?%s", MetadataHost, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata", "true")

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", time.Time{}, fmt.Errorf("status %s: %s", resp.Status, body)
	}
	var tr struct {
		AccessToken string      `json:"access_token"`
		ExpiresIn   json.Number `json:"expires_in"`
		ExpiresOn   string      `json:"expires_on"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", time.Time{}, err
	}
	if tr.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("empty access token")
	}

	exp := parseExpiry(tr.ExpiresOn, tr.ExpiresIn)
	return tr.AccessToken, exp, nil
}

func parseExpiry(expiresOn string, expiresIn json.Number) time.Time {
	if expiresOn != "" {
		if ts, err := strconv.ParseInt(expiresOn, 10, 64); err == nil && ts > 0 {
			return time.Unix(ts, 0)
		}
		if t, err := time.Parse("01/02/2006 15:04:05 -07:00", expiresOn); err == nil {
			return t
		}
	}
	if expiresIn != "" {
		if secs, err := expiresIn.Int64(); err == nil && secs > 0 {
			return time.Now().Add(time.Duration(secs) * time.Second)
		}
	}
	return time.Now().Add(time.Minute)
}

func getCachedToken(key string) (string, time.Time) {
	tokenCache.Lock()
	defer tokenCache.Unlock()
	ct, ok := tokenCache.m[key]
	if !ok {
		return "", time.Time{}
	}
	return ct.token, ct.exp
}

func setCachedToken(key, tok string, exp time.Time) {
	tokenCache.Lock()
	tokenCache.m[key] = cachedToken{token: tok, exp: exp}
	tokenCache.Unlock()
}

func init() { authplugins.RegisterOutgoing(&AzureOIDC{}) }
