package gcptoken

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
)

// gcpTokenParams configures the GCP token plugin.
type gcpTokenParams struct {
	Header string `json:"header"`
	Prefix string `json:"prefix"`
}

// GCPToken obtains an OAuth access token from the GCP metadata server
// and attaches it to outgoing requests.
type GCPToken struct{}

// MetadataHost is the base URL for metadata requests.
var MetadataHost = "http://metadata.google.internal"

// HTTPClient performs metadata HTTP requests. It can be swapped in tests.
var HTTPClient = &http.Client{Timeout: 5 * time.Second}

type cachedToken struct {
	token string
	exp   time.Time
}

var (
	mu    sync.Mutex
	cache cachedToken
)

func (g *GCPToken) Name() string { return "gcp_token" }

func (g *GCPToken) RequiredParams() []string { return nil }

func (g *GCPToken) OptionalParams() []string { return []string{"header", "prefix"} }

func (g *GCPToken) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[gcpTokenParams](m)
	if err != nil {
		return nil, err
	}
	if p.Header == "" {
		p.Header = "Authorization"
	}
	if p.Prefix == "" {
		p.Prefix = "Bearer "
	}
	return p, nil
}

func (g *GCPToken) AddAuth(ctx context.Context, r *http.Request, params interface{}) error {
	cfg, ok := params.(*gcpTokenParams)
	if !ok {
		return fmt.Errorf("invalid config")
	}
	tok, exp := getCachedToken()
	if tok == "" || time.Now().After(exp.Add(-1*time.Minute)) {
		var err error
		tok, exp, err = fetchToken()
		if err != nil {
			return err
		}
		setCachedToken(tok, exp)
	}
	r.Header.Set(cfg.Header, cfg.Prefix+tok)
	return nil
}

func fetchToken() (string, time.Time, error) {
	req, err := http.NewRequest("GET", MetadataHost+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
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
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", time.Time{}, err
	}
	return tr.AccessToken, time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second), nil
}

func getCachedToken() (string, time.Time) {
	mu.Lock()
	defer mu.Unlock()
	return cache.token, cache.exp
}

func setCachedToken(tok string, exp time.Time) {
	mu.Lock()
	cache.token = tok
	cache.exp = exp
	mu.Unlock()
}

func init() { authplugins.RegisterOutgoing(&GCPToken{}) }
