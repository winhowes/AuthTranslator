package awsimds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
)

// awsIMDSParams configures the AWS IMDS plugin.
type awsIMDSParams struct {
	Header string `json:"header"`
	Prefix string `json:"prefix"`
}

// AWSIMDS fetches the IAM role session token from the AWS Instance Metadata
// Service (IMDSv2) and adds it to outgoing requests.
type AWSIMDS struct{}

// MetadataHost is the base URL for the AWS metadata service. It can be
// overridden in tests.
var MetadataHost = "http://169.254.169.254"

// HTTPClient is used for all metadata requests.
var HTTPClient = &http.Client{Timeout: 5 * time.Second}

var tokenCache = struct {
	sync.Mutex
	ct cachedToken
}{ct: cachedToken{}}

type cachedToken struct {
	token string
	exp   time.Time
}

// AWSOIDC is kept as a backward-compatible alias for configurations still
// referencing the old plugin name. It delegates all behavior to AWSIMDS but
// advertises the legacy `aws_oidc` name.
type AWSOIDC struct{ AWSIMDS }

func (a *AWSOIDC) Name() string { return "aws_oidc" }

func (a *AWSIMDS) Name() string { return "aws_imds" }

func (a *AWSIMDS) RequiredParams() []string { return nil }

func (a *AWSIMDS) OptionalParams() []string { return []string{"header", "prefix"} }

func (a *AWSIMDS) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[awsIMDSParams](m)
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

func (a *AWSIMDS) AddAuth(ctx context.Context, r *http.Request, params interface{}) error {
	cfg, ok := params.(*awsIMDSParams)
	if !ok {
		return fmt.Errorf("invalid config")
	}
	tok, exp := getCachedToken()
	if tok == "" || time.Now().After(exp.Add(-1*time.Minute)) {
		var err error
		tok, exp, err = fetchToken(ctx)
		if err != nil {
			return err
		}
		setCachedToken(tok, exp)
	}
	r.Header.Set(cfg.Header, cfg.Prefix+tok)
	return nil
}

func fetchToken(ctx context.Context) (string, time.Time, error) {
	metaToken, err := fetchMetadataToken(ctx)
	if err != nil {
		return "", time.Time{}, err
	}

	roleName, err := fetchRoleName(ctx, metaToken)
	if err != nil {
		return "", time.Time{}, err
	}

	credentials, err := fetchRoleCredentials(ctx, metaToken, roleName)
	if err != nil {
		return "", time.Time{}, err
	}

	if credentials.Token == "" {
		return "", time.Time{}, fmt.Errorf("empty session token from IMDS for role %s", roleName)
	}

	exp, err := time.Parse(time.RFC3339, credentials.Expiration)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parse expiration: %w", err)
	}

	return credentials.Token, exp, nil
}

func fetchMetadataToken(ctx context.Context) (string, error) {
	tokenURL := fmt.Sprintf("%s/latest/api/token", MetadataHost)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, tokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token fetch status %s: %s", resp.Status, body)
	}

	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(tokenBytes), nil
}

func fetchRoleName(ctx context.Context, metaToken string) (string, error) {
	roleURL := fmt.Sprintf("%s/latest/meta-data/iam/security-credentials/", MetadataHost)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, roleURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token", metaToken)

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("role name status %s: %s", resp.Status, body)
	}

	roleBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	roleName := strings.TrimSpace(string(roleBytes))
	if roleName == "" {
		return "", fmt.Errorf("empty role name from IMDS")
	}
	return roleName, nil
}

type roleCredentials struct {
	Expiration string `json:"Expiration"`
	Token      string `json:"Token"`
}

func fetchRoleCredentials(ctx context.Context, metaToken, roleName string) (*roleCredentials, error) {
	credsURL := fmt.Sprintf("%s/latest/meta-data/iam/security-credentials/%s", MetadataHost, roleName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, credsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-aws-ec2-metadata-token", metaToken)

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("role credentials status %s: %s", resp.Status, body)
	}

	var rc roleCredentials
	if err := json.NewDecoder(resp.Body).Decode(&rc); err != nil {
		return nil, err
	}
	if rc.Expiration == "" {
		return nil, fmt.Errorf("missing expiration in role credentials")
	}
	return &rc, nil
}

func getCachedToken() (string, time.Time) {
	tokenCache.Lock()
	defer tokenCache.Unlock()
	return tokenCache.ct.token, tokenCache.ct.exp
}

func setCachedToken(tok string, exp time.Time) {
	tokenCache.Lock()
	tokenCache.ct = cachedToken{token: tok, exp: exp}
	tokenCache.Unlock()
}

func init() {
	authplugins.RegisterOutgoing(&AWSIMDS{})
	authplugins.RegisterOutgoing(&AWSOIDC{})
}
