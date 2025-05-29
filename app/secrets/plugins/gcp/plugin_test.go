package plugins

import (
	"context"
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
	oldDef := http.DefaultClient
	old := HTTPClient
	u, _ := url.Parse(ts.URL)
	c := &http.Client{Transport: &gcpRewriteTransport{rt: ts.Client().Transport, scheme: u.Scheme, host: u.Host}}
	http.DefaultClient = c
	HTTPClient = c
	return func() {
		http.DefaultClient = oldDef
		HTTPClient = old
	}
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
	got, err := p.Load(context.Background(), "projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher")
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
	if _, err := p.Load(context.Background(), "projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGCPKMSInvalidID(t *testing.T) {
	p := gcpKMSPlugin{}
	if _, err := p.Load(context.Background(), "invalid"); err == nil {
		t.Fatal("expected error for invalid id")
	}
}

func TestGCPKMSTokenDecodeError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			w.Write([]byte("notjson"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()
	restore := setGCPTestClient(ts)
	defer restore()

	p := gcpKMSPlugin{}
	if _, err := p.Load(context.Background(), "projects/p/k:cipher"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGCPKMSDecryptDecodeError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case strings.HasSuffix(r.URL.Path, ":decrypt"):
			w.Write([]byte("badjson"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	restore := setGCPTestClient(ts)
	defer restore()

	p := gcpKMSPlugin{}
	if _, err := p.Load(context.Background(), "projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGCPKMSInvalidPlaintext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case strings.HasSuffix(r.URL.Path, ":decrypt"):
			json.NewEncoder(w).Encode(map[string]string{"plaintext": "!bad"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	restore := setGCPTestClient(ts)
	defer restore()

	p := gcpKMSPlugin{}
	if _, err := p.Load(context.Background(), "projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher"); err == nil {
		t.Fatal("expected base64 error")
	}
}
