package awsoidc

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testClaims struct {
	Exp int64 `json:"exp"`
}

func makeJWT(exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":` + fmt.Sprintf("%d", exp.Unix()) + `}`))
	return strings.Join([]string{header, claims, "sig"}, ".")
}

func TestAddAuthFetchesAndCachesToken(t *testing.T) {
	now := time.Now().Add(2 * time.Minute)
	jwt := makeJWT(now)

	metaToken := "meta123"
	aud := "urn:test"
	var requestCount int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			requestCount++
			if r.Method != http.MethodPut {
				t.Fatalf("expected PUT for token, got %s", r.Method)
			}
			if ttl := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds"); ttl == "" {
				t.Fatalf("missing TTL header")
			}
			w.Write([]byte(metaToken))
		case "/latest/meta-data/iam/security-credentials/oidc":
			requestCount++
			if got := r.Header.Get("X-aws-ec2-metadata-token"); got != metaToken {
				t.Fatalf("expected metadata token %q, got %q", metaToken, got)
			}
			if got := r.URL.Query().Get("audience"); got != aud {
				t.Fatalf("expected audience %s, got %s", aud, got)
			}
			w.Write([]byte(jwt))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	MetadataHost = srv.URL
	HTTPClient = srv.Client()
	tokenCache.m = map[string]cachedToken{}

	plugin := &AWSOIDC{}
	paramsRaw, err := plugin.ParseParams(map[string]interface{}{"audience": aud})
	if err != nil {
		t.Fatalf("parse params: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err := plugin.AddAuth(context.Background(), req, paramsRaw); err != nil {
		t.Fatalf("AddAuth: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer "+jwt {
		t.Fatalf("unexpected header: %s", got)
	}
	if requestCount != 2 {
		t.Fatalf("expected 2 metadata requests, got %d", requestCount)
	}

	// Second call should use cache.
	req2, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err := plugin.AddAuth(context.Background(), req2, paramsRaw); err != nil {
		t.Fatalf("AddAuth second: %v", err)
	}
	if requestCount != 2 {
		t.Fatalf("expected cached token, still %d requests", requestCount)
	}
}

func TestExpiresSoonTriggersRefresh(t *testing.T) {
	expSoon := time.Now().Add(30 * time.Second)
	jwt1 := makeJWT(expSoon)
	jwt2 := makeJWT(time.Now().Add(10 * time.Minute))
	metaToken := "meta123"
	aud := "urn:test"
	var stage int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			w.Write([]byte(metaToken))
		case "/latest/meta-data/iam/security-credentials/oidc":
			if stage == 0 {
				w.Write([]byte(jwt1))
			} else {
				w.Write([]byte(jwt2))
			}
			stage++
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	MetadataHost = srv.URL
	HTTPClient = srv.Client()
	tokenCache.m = map[string]cachedToken{}

	plugin := &AWSOIDC{}
	paramsRaw, err := plugin.ParseParams(map[string]interface{}{"audience": aud})
	if err != nil {
		t.Fatalf("parse params: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err := plugin.AddAuth(context.Background(), req, paramsRaw); err != nil {
		t.Fatalf("AddAuth: %v", err)
	}
	req2, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err := plugin.AddAuth(context.Background(), req2, paramsRaw); err != nil {
		t.Fatalf("AddAuth second: %v", err)
	}
	if stage != 2 {
		t.Fatalf("expected token refresh, stage %d", stage)
	}
}

func TestErrorResponses(t *testing.T) {
	aud := "urn:test"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("no token"))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	MetadataHost = srv.URL
	HTTPClient = srv.Client()
	tokenCache.m = map[string]cachedToken{}

	plugin := &AWSOIDC{}
	paramsRaw, err := plugin.ParseParams(map[string]interface{}{"audience": aud})
	if err != nil {
		t.Fatalf("parse params: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err := plugin.AddAuth(context.Background(), req, paramsRaw); err == nil {
		t.Fatalf("expected error from metadata token fetch")
	}
}
