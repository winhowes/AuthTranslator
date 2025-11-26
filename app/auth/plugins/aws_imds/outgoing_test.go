package awsimds

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAddAuthFetchesAndSigns(t *testing.T) {
	expires := time.Now().Add(2 * time.Minute).UTC().Truncate(time.Second)
	metaToken := "meta123"
	roleName := "example-role"
	creds := map[string]interface{}{
		"AccessKeyId":     "AKIDEXAMPLE",
		"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"Token":           "sts-session-token",
		"Expiration":      expires.Format(time.RFC3339),
	}
	var requestCount int
	fixedNow := time.Date(2023, 1, 2, 15, 4, 5, 0, time.UTC)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			requestCount++
			w.Write([]byte(metaToken))
		case "/latest/meta-data/iam/security-credentials/":
			requestCount++
			w.Write([]byte(roleName))
		case "/latest/meta-data/iam/security-credentials/" + roleName:
			requestCount++
			json.NewEncoder(w).Encode(creds)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	MetadataHost = srv.URL
	HTTPClient = srv.Client()
	credsCache.cc = cachedCreds{}
	prevNow := nowFunc
	nowFunc = func() time.Time { return fixedNow }
	defer func() { nowFunc = prevNow }()

	plugin := &AWSIMDS{}
	paramsRaw, err := plugin.ParseParams(map[string]interface{}{})
	if err != nil {
		t.Fatalf("parse params: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://s3.us-west-2.amazonaws.com/example", nil)

	if err := plugin.AddAuth(context.Background(), req, paramsRaw); err != nil {
		t.Fatalf("AddAuth: %v", err)
	}

	if got := req.Header.Get("X-Amz-Security-Token"); got != creds["Token"] {
		t.Fatalf("missing security token header: %s", got)
	}
	authz := req.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("expected SigV4 auth header, got %s", authz)
	}
	if !strings.Contains(authz, "Credential=AKIDEXAMPLE/20230102/us-west-2/s3/aws4_request") {
		t.Fatalf("unexpected credential scope: %s", authz)
	}
	if !strings.Contains(authz, "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token") {
		t.Fatalf("missing signed headers: %s", authz)
	}
	if !strings.Contains(authz, "Signature=") {
		t.Fatalf("missing signature: %s", authz)
	}
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("unexpected payload hash: %s", got)
	}

	if requestCount != 3 {
		t.Fatalf("expected 3 metadata requests, got %d", requestCount)
	}

	// Second call should use cache.
	req2, _ := http.NewRequest(http.MethodGet, "https://s3.us-west-2.amazonaws.com/example", nil)
	if err := plugin.AddAuth(context.Background(), req2, paramsRaw); err != nil {
		t.Fatalf("AddAuth second: %v", err)
	}
	if requestCount != 3 {
		t.Fatalf("expected cached credentials reuse, got %d metadata calls", requestCount)
	}
}

func TestExpiresSoonTriggersRefresh(t *testing.T) {
	expSoon := time.Now().Add(30 * time.Second).UTC().Truncate(time.Second)
	expLater := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	metaToken := "meta123"
	roleName := "role"
	credIndex := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			w.Write([]byte(metaToken))
		case "/latest/meta-data/iam/security-credentials/":
			w.Write([]byte(roleName))
		case "/latest/meta-data/iam/security-credentials/" + roleName:
			exp := expSoon
			if credIndex > 0 {
				exp = expLater
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"AccessKeyId":     "AKID",
				"SecretAccessKey": "SECRET",
				"Token":           []string{"first", "second"}[credIndex],
				"Expiration":      exp.Format(time.RFC3339),
			})
			credIndex++
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	MetadataHost = srv.URL
	HTTPClient = srv.Client()
	credsCache.cc = cachedCreds{}
	prevNow := nowFunc
	current := time.Now()
	nowFunc = func() time.Time { return current }
	defer func() { nowFunc = prevNow }()

	plugin := &AWSIMDS{}
	paramsRaw, err := plugin.ParseParams(map[string]interface{}{})
	if err != nil {
		t.Fatalf("parse params: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://s3.us-east-1.amazonaws.com", nil)
	if err := plugin.AddAuth(context.Background(), req, paramsRaw); err != nil {
		t.Fatalf("AddAuth: %v", err)
	}
	current = current.Add(2 * time.Minute)
	req2, _ := http.NewRequest(http.MethodGet, "https://s3.us-east-1.amazonaws.com", nil)
	if err := plugin.AddAuth(context.Background(), req2, paramsRaw); err != nil {
		t.Fatalf("AddAuth second: %v", err)
	}
	if credIndex != 2 {
		t.Fatalf("expected credential refresh, got %d", credIndex)
	}
}

func TestDetermineRegionServiceWithResourcePrefix(t *testing.T) {
	cfg := &awsIMDSParams{}
	region, service, err := determineRegionService("mybucket.s3.us-west-2.amazonaws.com", cfg)
	if err != nil {
		t.Fatalf("determineRegionService: %v", err)
	}
	if region != "us-west-2" || service != "s3" {
		t.Fatalf("unexpected derived values region=%s service=%s", region, service)
	}
}

func TestDetermineRegionServiceDualstack(t *testing.T) {
	cfg := &awsIMDSParams{}
	region, service, err := determineRegionService("s3.dualstack.us-east-1.amazonaws.com", cfg)
	if err != nil {
		t.Fatalf("determineRegionService: %v", err)
	}
	if region != "us-east-1" || service != "s3" {
		t.Fatalf("unexpected derived values region=%s service=%s", region, service)
	}
}

func TestErrorResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("no token"))
		case "/latest/meta-data/iam/security-credentials/":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("no role"))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	MetadataHost = srv.URL
	HTTPClient = srv.Client()
	credsCache.cc = cachedCreds{}

	plugin := &AWSIMDS{}
	paramsRaw, err := plugin.ParseParams(map[string]interface{}{})
	if err != nil {
		t.Fatalf("parse params: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err := plugin.AddAuth(context.Background(), req, paramsRaw); err == nil {
		t.Fatalf("expected error from metadata token fetch")
	}
}

func TestCanonicalURIPreservesTrailingAndRepeatedSlashes(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		{name: "empty", path: "", want: "/"},
		{name: "root", path: "/", want: "/"},
		{name: "trailing slash", path: "/foo/bar/", want: "/foo/bar/"},
		{name: "repeated slashes", path: "/foo//bar//baz", want: "/foo//bar//baz"},
		{name: "dot segment", path: "/foo/./bar", want: "/foo/bar"},
		{name: "parent segment", path: "/foo/../bar", want: "/bar"},
		{name: "parent with trailing", path: "/foo/bar/../", want: "/foo/"},
		{name: "no leading slash", path: "foo/bar", want: "/foo/bar"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := &url.URL{Path: tc.path}
			if got := canonicalURI(u); got != tc.want {
				t.Fatalf("canonicalURI(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}
