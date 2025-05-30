package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

type rewriteTransport struct {
	rt     http.RoundTripper
	scheme string
	host   string
}

func (t *rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = t.scheme
	r.URL.Host = t.host
	return t.rt.RoundTrip(r)
}

func setTestClient(ts *httptest.Server) func() {
	oldClient := httpClient
	u, _ := url.Parse(ts.URL)
	httpClient = &http.Client{Transport: &rewriteTransport{rt: ts.Client().Transport, scheme: u.Scheme, host: u.Host}}
	return func() { httpClient = oldClient }
}

func writeFiles(t *testing.T, token, ca string) func() {
	t.Helper()
	oldTok := tokenPath
	oldCA := caPath
	tokFile := t.TempDir() + "/token"
	caFile := t.TempDir() + "/ca.crt"
	if err := os.WriteFile(tokFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, []byte(ca), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenPath = tokFile
	caPath = caFile
	return func() {
		tokenPath = oldTok
		caPath = oldCA
	}
}

func TestK8sLoad(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing auth header")
		}
		if r.URL.Path != "/api/v1/namespaces/ns/secrets/sec" {
			t.Errorf("bad path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]map[string]string{"data": {"foo": "YmFy"}})
	}))
	defer ts.Close()
	restoreClient := setTestClient(ts)
	defer restoreClient()
	restoreFiles := writeFiles(t, "tok", "")
	defer restoreFiles()
	t.Setenv("KUBERNETES_SERVICE_HOST", "k8s")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	p := k8sPlugin{}
	got, err := p.Load(context.Background(), "ns/sec#foo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "bar" {
		t.Fatalf("expected bar, got %s", got)
	}
}

func TestK8sLoadMissingKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]map[string]string{"data": {"foo": "YmFy"}})
	}))
	defer ts.Close()
	restoreClient := setTestClient(ts)
	defer restoreClient()
	restoreFiles := writeFiles(t, "tok", "")
	defer restoreFiles()
	t.Setenv("KUBERNETES_SERVICE_HOST", "k8s")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	p := k8sPlugin{}
	if _, err := p.Load(context.Background(), "ns/sec#missing"); err == nil {
		t.Fatal("expected error")
	}
}

func TestK8sLoadBadID(t *testing.T) {
	p := k8sPlugin{}
	if _, err := p.Load(context.Background(), "badid"); err == nil {
		t.Fatal("expected error")
	}
}

func TestK8sRequestError(t *testing.T) {
	oldReq := newRequest
	newRequest = func(context.Context, string, string, io.Reader) (*http.Request, error) {
		return nil, fmt.Errorf("req")
	}
	defer func() { newRequest = oldReq }()
	restoreFiles := writeFiles(t, "tok", "")
	defer restoreFiles()
	t.Setenv("KUBERNETES_SERVICE_HOST", "k8s")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	p := k8sPlugin{}
	if _, err := p.Load(context.Background(), "ns/sec#foo"); err == nil {
		t.Fatal("expected error")
	}
}
