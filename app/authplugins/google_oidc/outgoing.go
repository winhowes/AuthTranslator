package googleoidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/winhowes/AuthTranslator/app/authplugins"
)

// googleOIDCParams holds configuration for the Google OIDC plugin.
type googleOIDCParams struct {
	Audience string `json:"audience"`
	Header   string `json:"header"`
	Prefix   string `json:"prefix"`
}

// GoogleOIDC obtains an identity token from the GCP metadata server and sets it
// on outgoing requests.
type GoogleOIDC struct{}

// MetadataHost is the base URL for the metadata server. It is overridden in tests.
var MetadataHost = "http://metadata.google.internal"

// HTTPClient is used for metadata requests and can be overridden in tests.
var HTTPClient = &http.Client{Timeout: 5 * time.Second}

type cachedToken struct {
	token string
	exp   time.Time
}

var tokenCache = struct {
	sync.Mutex
	m map[string]cachedToken
}{m: make(map[string]cachedToken)}

func (g *GoogleOIDC) Name() string { return "google_oidc" }

func (g *GoogleOIDC) RequiredParams() []string {
	return []string{"audience"}
}

func (g *GoogleOIDC) OptionalParams() []string { return []string{"header", "prefix"} }

func (g *GoogleOIDC) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[googleOIDCParams](m)
	if err != nil {
		return nil, err
	}
	if p.Audience == "" {
		return nil, fmt.Errorf("missing audience")
	}
	if p.Header == "" {
		p.Header = "Authorization"
	}
	if p.Prefix == "" {
		p.Prefix = "Bearer "
	}
	return p, nil
}

func (g *GoogleOIDC) AddAuth(r *http.Request, params interface{}) {
	cfg, ok := params.(*googleOIDCParams)
	if !ok {
		return
	}
	tok, exp := getCachedToken(cfg.Audience)
	if tok == "" || time.Now().After(exp) {
		var err error
		tok, exp, err = fetchToken(cfg.Audience)
		if err != nil {
			return
		}
		setCachedToken(cfg.Audience, tok, exp)
	}
	r.Header.Set(cfg.Header, cfg.Prefix+tok)
}

func fetchToken(aud string) (string, time.Time, error) {
	metaURL := fmt.Sprintf("%s/computeMetadata/v1/instance/service-accounts/default/identity?audience=%s", MetadataHost, url.QueryEscape(aud))
	req, err := http.NewRequest("GET", metaURL, nil)
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
		return "", time.Time{}, fmt.Errorf("status %s", resp.Status)
	}
	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, err
	}
	tok := string(tokenBytes)
	return tok, parseExpiry(tok), nil
}

func parseExpiry(tok string) time.Time {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return time.Now().Add(time.Minute)
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Now().Add(time.Minute)
	}
	var c struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(data, &c); err != nil || c.Exp == 0 {
		return time.Now().Add(time.Minute)
	}
	return time.Unix(c.Exp, 0)
}

func getCachedToken(aud string) (string, time.Time) {
	tokenCache.Lock()
	defer tokenCache.Unlock()
	ct, ok := tokenCache.m[aud]
	if !ok {
		return "", time.Time{}
	}
	return ct.token, ct.exp
}

func setCachedToken(aud, tok string, exp time.Time) {
	tokenCache.Lock()
	tokenCache.m[aud] = cachedToken{token: tok, exp: exp}
	tokenCache.Unlock()
}

func init() { authplugins.RegisterOutgoing(&GoogleOIDC{}) }
