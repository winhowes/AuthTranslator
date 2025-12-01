package azuremanagedidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
)

// azureManagedIdentityParams configures the Azure Managed Identity plugin.
type azureManagedIdentityParams struct {
	Resource string `json:"resource"`
	ClientID string `json:"client_id"`
	Header   string `json:"header"`
	Prefix   string `json:"prefix"`
}

// AzureManagedIdentity obtains an access token from the Azure Instance Metadata
// Service and attaches it to outgoing requests.
type AzureManagedIdentity struct{}

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

func (a *AzureManagedIdentity) Name() string { return "azure_managed_identity" }

func (a *AzureManagedIdentity) RequiredParams() []string { return []string{"resource"} }

func (a *AzureManagedIdentity) OptionalParams() []string {
	return []string{"client_id", "header", "prefix"}
}

func (a *AzureManagedIdentity) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[azureManagedIdentityParams](m)
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

func (a *AzureManagedIdentity) AddAuth(ctx context.Context, r *http.Request, params interface{}) error {
	cfg, ok := params.(*azureManagedIdentityParams)
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
	metaURL, headers, err := metadataRequest(resource, clientID)
	if err != nil {
		return "", time.Time{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

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

func metadataRequest(resource, clientID string) (string, map[string]string, error) {
	q := url.Values{}
	q.Set("resource", resource)
	if clientID != "" {
		q.Set("client_id", clientID)
	}

	if endpoint := os.Getenv("IDENTITY_ENDPOINT"); endpoint != "" {
		header := os.Getenv("IDENTITY_HEADER")
		if header == "" {
			return "", nil, fmt.Errorf("missing IDENTITY_HEADER for IDENTITY_ENDPOINT")
		}
		q.Set("api-version", "2019-08-01")
		return fmt.Sprintf("%s?%s", endpoint, q.Encode()), map[string]string{"X-IDENTITY-HEADER": header}, nil
	}

	if endpoint := os.Getenv("MSI_ENDPOINT"); endpoint != "" {
		secret := os.Getenv("MSI_SECRET")
		if secret == "" {
			return "", nil, fmt.Errorf("missing MSI_SECRET for MSI_ENDPOINT")
		}
		q.Set("api-version", "2017-09-01")
		return fmt.Sprintf("%s?%s", endpoint, q.Encode()), map[string]string{"Secret": secret}, nil
	}

	q.Set("api-version", "2018-02-01")
	return fmt.Sprintf("%s/metadata/identity/oauth2/token?%s", MetadataHost, q.Encode()), map[string]string{"Metadata": "true"}, nil
}

func parseExpiry(expiresOn string, expiresIn json.Number) time.Time {
	if expiresOn != "" {
		if ts, err := strconv.ParseInt(expiresOn, 10, 64); err == nil && ts > 0 {
			return time.Unix(ts, 0)
		}
		if ts, err := time.Parse("01/02/2006 15:04:05 -07:00", expiresOn); err == nil {
			return ts
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

func init() { authplugins.RegisterOutgoing(&AzureManagedIdentity{}) }
