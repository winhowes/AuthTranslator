package googleoidc

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/winhowes/AuthTransformer/app/authplugins"
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
	metaURL := fmt.Sprintf("%s/computeMetadata/v1/instance/service-accounts/default/identity?audience=%s", MetadataHost, url.QueryEscape(cfg.Audience))
	req, err := http.NewRequest("GET", metaURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	token, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	r.Header.Set(cfg.Header, cfg.Prefix+string(token))
}

func init() { authplugins.RegisterOutgoing(&GoogleOIDC{}) }
