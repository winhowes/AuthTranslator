package awsimds

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
)

// awsIMDSParams configures the AWS IMDS plugin.
type awsIMDSParams struct {
	Region  string `json:"region"`
	Service string `json:"service"`
}

// AWSIMDS fetches the IAM role session token from the AWS Instance Metadata
// Service (IMDSv2) and adds it to outgoing requests.
type AWSIMDS struct{}

// MetadataHost is the base URL for the AWS metadata service. It can be
// overridden in tests.
var MetadataHost = "http://169.254.169.254"

// HTTPClient is used for all metadata requests.
var HTTPClient = &http.Client{
	Timeout:   5 * time.Second,
	Transport: defaultIMDSTransport(),
}

var nowFunc = time.Now

// AWSOIDC is kept as a backward-compatible alias for configurations still
// referencing the old plugin name. It delegates all behavior to AWSIMDS but
// advertises the legacy `aws_oidc` name.
type AWSOIDC struct{ AWSIMDS }

func (a *AWSOIDC) Name() string { return "aws_oidc" }

func (a *AWSIMDS) Name() string { return "aws_imds" }

func (a *AWSIMDS) RequiredParams() []string { return nil }

func (a *AWSIMDS) OptionalParams() []string { return []string{"region", "service"} }

func (a *AWSIMDS) ParseParams(m map[string]interface{}) (interface{}, error) {
	return authplugins.ParseParams[awsIMDSParams](m)
}

func (a *AWSIMDS) AddAuth(ctx context.Context, r *http.Request, params interface{}) error {
	cfg, ok := params.(*awsIMDSParams)
	if !ok {
		return fmt.Errorf("invalid config")
	}
	creds, exp := getCachedCreds()
	if creds == nil || nowFunc().After(exp.Add(-1*time.Minute)) {
		var err error
		creds, exp, err = fetchCredentials(ctx)
		if err != nil {
			return err
		}
		setCachedCreds(creds, exp)
	}
	region, service, err := determineRegionService(r.URL.Host, cfg)
	if err != nil {
		return err
	}
	return signRequest(r, region, service, creds)
}

func fetchCredentials(ctx context.Context) (*roleCredentials, time.Time, error) {
	metaToken, err := fetchMetadataToken(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}

	roleName, err := fetchRoleName(ctx, metaToken)
	if err != nil {
		return nil, time.Time{}, err
	}

	credentials, err := fetchRoleCredentials(ctx, metaToken, roleName)
	if err != nil {
		return nil, time.Time{}, err
	}

	if credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" || credentials.Token == "" {
		return nil, time.Time{}, fmt.Errorf("incomplete credentials from IMDS for role %s", roleName)
	}

	exp, err := time.Parse(time.RFC3339, credentials.Expiration)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse expiration: %w", err)
	}

	return credentials, exp, nil
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
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
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

type cachedCreds struct {
	creds *roleCredentials
	exp   time.Time
}

var credsCache = struct {
	sync.Mutex
	cc cachedCreds
}{cc: cachedCreds{}}

func getCachedCreds() (*roleCredentials, time.Time) {
	credsCache.Lock()
	defer credsCache.Unlock()
	return credsCache.cc.creds, credsCache.cc.exp
}

func setCachedCreds(creds *roleCredentials, exp time.Time) {
	credsCache.Lock()
	credsCache.cc = cachedCreds{creds: creds, exp: exp}
	credsCache.Unlock()
}

func determineRegionService(host string, cfg *awsIMDSParams) (string, string, error) {
	region := strings.TrimSpace(cfg.Region)
	service := strings.TrimSpace(cfg.Service)

	if region != "" && service != "" {
		return region, service, nil
	}

	host = strings.Split(host, ":")[0] // strip port if present
	parts := strings.Split(host, ".")
	if len(parts) >= 4 && parts[len(parts)-2] == "amazonaws" {
		// Use the right-most service and region portions to support hosts with
		// additional labels (e.g., bucket.s3.us-west-2.amazonaws.com).
		serviceIdx := len(parts) - 4
		regionIdx := len(parts) - 3
		if serviceIdx >= 0 && regionIdx >= 0 {
			if service == "" {
				candidate := parts[serviceIdx]
				if candidate == "dualstack" && serviceIdx > 0 {
					candidate = parts[serviceIdx-1]
				}
				service = candidate
			}
			if region == "" {
				region = parts[regionIdx]
			}
		}
	}

	if region == "" || service == "" {
		return "", "", fmt.Errorf("aws_imds requires region and service; set params or use standard AWS hostname")
	}

	return region, service, nil
}

func signRequest(r *http.Request, region, service string, creds *roleCredentials) error {
	now := nowFunc().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	if r.Header == nil {
		r.Header = http.Header{}
	}

	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}
	if host == "" {
		return fmt.Errorf("request host is required for signing")
	}
	r.Header.Set("Host", host)
	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("X-Amz-Security-Token", creds.Token)

	body, err := readBody(r)
	if err != nil {
		return err
	}
	payloadHash := hashSHA256Hex(body)
	r.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signedHeaders, canonicalHeaders := canonicalizeHeaders(r.Header)
	canonicalQuery := canonicalizeQuery(r.URL)
	canonicalURI := canonicalURI(r.URL)
	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hashSHA256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := buildSigningKey(creds.SecretAccessKey, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", creds.AccessKeyID, credentialScope, signedHeaders, signature)
	r.Header.Set("Authorization", authHeader)

	return nil
}

func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return []byte{}, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return body, nil
}

func canonicalizeHeaders(h http.Header) (string, string) {
	lowerVals := make(map[string][]string, len(h))
	for k, v := range h {
		lowerVals[strings.ToLower(k)] = v
	}
	keys := make([]string, 0, len(lowerVals))
	for k := range lowerVals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, k := range keys {
		values := lowerVals[k]
		for i := range values {
			values[i] = strings.Join(strings.Fields(values[i]), " ")
		}
		canonical.WriteString(k)
		canonical.WriteString(":")
		canonical.WriteString(strings.Join(values, ","))
		canonical.WriteString("\n")
	}
	return strings.Join(keys, ";"), canonical.String()
}

func canonicalizeQuery(u *url.URL) string {
	if u == nil {
		return ""
	}
	values, _ := url.ParseQuery(u.RawQuery)
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := values[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, fmt.Sprintf("%s=%s", escapeQueryComponent(k), escapeQueryComponent(v)))
		}
	}
	return strings.Join(parts, "&")
}

func escapeQueryComponent(v string) string {
	escaped := url.QueryEscape(v)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "*", "%2A")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	return escaped
}

func canonicalURI(u *url.URL) string {
	if u == nil {
		return "/"
	}
	uri := u.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	return removeDotSegments(uri)
}

func removeDotSegments(path string) string {
	if path == "" {
		return ""
	}
	input := path
	output := ""
	for len(input) > 0 {
		switch {
		case strings.HasPrefix(input, "../"):
			input = input[3:]
		case strings.HasPrefix(input, "./"):
			input = input[2:]
		case strings.HasPrefix(input, "/./"):
			input = "/" + input[3:]
		case input == "/.":
			input = "/"
		case strings.HasPrefix(input, "/../"):
			input = "/" + input[4:]
			output = removeLastSegment(output)
		case input == "/..":
			input = "/"
			output = removeLastSegment(output)
		case input == "." || input == "..":
			input = ""
		default:
			var segment string
			if strings.HasPrefix(input, "/") {
				if idx := strings.Index(input[1:], "/"); idx != -1 {
					segment = input[:idx+1]
					input = input[idx+1:]
				} else {
					segment = input
					input = ""
				}
			} else {
				if idx := strings.IndexByte(input, '/'); idx != -1 {
					segment = input[:idx]
					input = input[idx:]
				} else {
					segment = input
					input = ""
				}
			}
			output += segment
		}
	}
	return output
}

func removeLastSegment(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx == -1 {
		return ""
	}
	return path[:idx]
}

func defaultIMDSTransport() *http.Transport {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		clone := t.Clone()
		clone.Proxy = nil
		return clone
	}

	return &http.Transport{Proxy: nil}
}

func hashSHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

func buildSigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

func init() {
	authplugins.RegisterOutgoing(&AWSIMDS{})
	authplugins.RegisterOutgoing(&AWSOIDC{})
}
