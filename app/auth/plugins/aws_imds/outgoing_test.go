package awsimds

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAddAuthFetchesAndCachesToken(t *testing.T) {
	expires := time.Now().Add(2 * time.Minute).UTC().Truncate(time.Second)
	sessionToken := "sts-session-token"
	metaToken := "meta123"
	roleName := "example-role"
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
		case "/latest/meta-data/iam/security-credentials/":
			requestCount++
			if got := r.Header.Get("X-aws-ec2-metadata-token"); got != metaToken {
				t.Fatalf("expected metadata token %q, got %q", metaToken, got)
			}
			w.Write([]byte(roleName))
		case "/latest/meta-data/iam/security-credentials/" + roleName:
			requestCount++
			if got := r.Header.Get("X-aws-ec2-metadata-token"); got != metaToken {
				t.Fatalf("expected metadata token %q, got %q", metaToken, got)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"Token":      sessionToken,
				"Expiration": expires.Format(time.RFC3339),
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	MetadataHost = srv.URL
	HTTPClient = srv.Client()
	tokenCache.ct = cachedToken{}

	plugin := &AWSIMDS{}
	paramsRaw, err := plugin.ParseParams(map[string]interface{}{})
	if err != nil {
		t.Fatalf("parse params: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err := plugin.AddAuth(context.Background(), req, paramsRaw); err != nil {
		t.Fatalf("AddAuth: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer "+sessionToken {
		t.Fatalf("unexpected header: %s", got)
	}
	if requestCount != 3 {
		t.Fatalf("expected 3 metadata requests, got %d", requestCount)
	}

	// Second call should use cache.
	req2, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err := plugin.AddAuth(context.Background(), req2, paramsRaw); err != nil {
		t.Fatalf("AddAuth second: %v", err)
	}
	if requestCount != 3 {
		t.Fatalf("expected cached token, still %d requests", requestCount)
	}
}

func TestExpiresSoonTriggersRefresh(t *testing.T) {
	expSoon := time.Now().Add(30 * time.Second).UTC().Truncate(time.Second)
	expLater := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	metaToken := "meta123"
	roleName := "role"
	sessionTokens := []string{"first", "second"}
	var credIndex int

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
				"Token":      sessionTokens[credIndex],
				"Expiration": exp.Format(time.RFC3339),
			})
			credIndex++
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	MetadataHost = srv.URL
	HTTPClient = srv.Client()
	tokenCache.ct = cachedToken{}

	plugin := &AWSIMDS{}
	paramsRaw, err := plugin.ParseParams(map[string]interface{}{})
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
	if credIndex != 2 {
		t.Fatalf("expected token refresh, stage %d", credIndex)
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
	tokenCache.ct = cachedToken{}

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
