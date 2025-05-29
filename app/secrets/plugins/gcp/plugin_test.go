package plugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

type errorRoundTripper struct{}

func (errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("network error")
}

type tokenThenError struct{ done bool }

func (t *tokenThenError) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.done {
		t.done = true
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rec).Encode(map[string]string{"access_token": "tok"})
		return rec.Result(), nil
	}
	return nil, fmt.Errorf("net err")
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

func TestGCPKMSDecryptFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case strings.HasSuffix(r.URL.Path, ":decrypt"):
			http.Error(w, "fail", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	restore := setGCPTestClient(ts)
	defer restore()

	p := gcpKMSPlugin{}
	if _, err := p.Load(context.Background(), "projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGCPKMSTokenRequestError(t *testing.T) {
	oldDef := http.DefaultClient
	old := HTTPClient
	c := &http.Client{Transport: errorRoundTripper{}}
	http.DefaultClient = c
	HTTPClient = c
	defer func() {
		http.DefaultClient = oldDef
		HTTPClient = old
	}()

	p := gcpKMSPlugin{}
	if _, err := p.Load(context.Background(), "projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGCPKMSMetadataRequestCreateError(t *testing.T) {
	old := httpNewRequest
	httpNewRequest = func(method, url string, body io.Reader) (*http.Request, error) { return nil, fmt.Errorf("bad req") }
	defer func() { httpNewRequest = old }()

	p := gcpKMSPlugin{}
	if _, err := p.Load(context.Background(), "projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGCPKMSDecryptRequestCreateError(t *testing.T) {
	count := 0
	oldReq := httpNewRequest
	httpNewRequest = func(method, url string, body io.Reader) (*http.Request, error) {
		count++
		if count == 1 {
			return oldReq(method, url, body)
		}
		return nil, fmt.Errorf("bad req")
	}
	defer func() { httpNewRequest = oldReq }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
	}))
	defer ts.Close()
	restore := setGCPTestClient(ts)
	defer restore()

	p := gcpKMSPlugin{}
	if _, err := p.Load(context.Background(), "projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGCPKMSDecryptNetworkError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	rt := &tokenThenError{}
	failing := &http.Client{Transport: &gcpRewriteTransport{rt: rt, scheme: u.Scheme, host: u.Host}}
	oldDef := http.DefaultClient
	old := HTTPClient
	http.DefaultClient = failing
	HTTPClient = failing
	defer func() { http.DefaultClient = oldDef; HTTPClient = old }()

	p := gcpKMSPlugin{}
	if _, err := p.Load(context.Background(), "projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGCPKMSMarshalError(t *testing.T) {
	oldM := jsonMarshal
	jsonMarshal = func(v any) ([]byte, error) { return nil, fmt.Errorf("bad") }
	defer func() { jsonMarshal = oldM }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
	}))
	defer ts.Close()
	restore := setGCPTestClient(ts)
	defer restore()

	p := gcpKMSPlugin{}
	if _, err := p.Load(context.Background(), "projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher"); err == nil {
		t.Fatal("expected error")
	}
}
