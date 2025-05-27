package plugins

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type gcpRewriteTransport struct {
	rt     http.RoundTripper
	scheme string
	host   string
}

func (t *gcpRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = t.scheme
	req.URL.Host = t.host
	return t.rt.RoundTrip(req)
}

func setGCPTestClient(ts *httptest.Server) func() {
	old := http.DefaultClient
	u, _ := url.Parse(ts.URL)
	http.DefaultClient = &http.Client{Transport: &gcpRewriteTransport{rt: ts.Client().Transport, scheme: u.Scheme, host: u.Host}}
	return func() { http.DefaultClient = old }
}

func TestGCPKMSLoad(t *testing.T) {
	plaintext := base64.StdEncoding.EncodeToString([]byte("secret"))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			if r.Header.Get("Metadata-Flavor") != "Google" {
				t.Errorf("missing metadata header")
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case strings.HasSuffix(r.URL.Path, ":decrypt"):
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("missing auth header")
			}
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "cipher") {
				t.Errorf("missing ciphertext in body")
			}
			json.NewEncoder(w).Encode(map[string]string{"plaintext": plaintext})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	restore := setGCPTestClient(ts)
	defer restore()

	p := gcpKMSPlugin{}
	got, err := p.Load("projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "secret" {
		t.Fatalf("expected secret, got %s", got)
	}
}

func TestGCPKMSLoadError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer ts.Close()
	restore := setGCPTestClient(ts)
	defer restore()

	p := gcpKMSPlugin{}
	if _, err := p.Load("projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher"); err == nil {
		t.Fatal("expected error")
	}
}
