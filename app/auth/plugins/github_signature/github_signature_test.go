package githubsignature

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestGitHubSignatureAuth(t *testing.T) {
	body := "hello"
	mac := hmac.New(sha256.New, []byte("key"))
	mac.Write([]byte(body))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	r := &http.Request{Header: http.Header{
		"X-Hub-Signature-256": []string{sig},
	}, Body: io.NopCloser(strings.NewReader(body))}

	p := GitHubSignatureAuth{}
	t.Setenv("SEC", "key")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
}

func TestGitHubSignatureAuthFail(t *testing.T) {
	body := "hello"
	mac := hmac.New(sha256.New, []byte("bad"))
	mac.Write([]byte(body))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	r := &http.Request{Header: http.Header{
		"X-Hub-Signature-256": []string{sig},
	}, Body: io.NopCloser(strings.NewReader(body))}

	p := GitHubSignatureAuth{}
	t.Setenv("SEC", "key")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}

func TestGitHubSignatureOptionalParams(t *testing.T) {
	p := GitHubSignatureAuth{}
	if got := p.OptionalParams(); len(got) != 2 || got[0] != "header" {
		t.Fatalf("unexpected optional params: %v", got)
	}
}

// errReadCloser returns an error on Read to trigger GetBody failures.
type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("err") }
func (errReadCloser) Close() error             { return nil }

func TestGitHubSignatureDefaults(t *testing.T) {
	p := GitHubSignatureAuth{}
	t.Setenv("SEC", "k")
	cfgI, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok := cfgI.(*githubSigParams)
	if !ok {
		t.Fatalf("unexpected type %T", cfgI)
	}
	if cfg.Header != "X-Hub-Signature-256" || cfg.Prefix != "sha256=" {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
}

func TestGitHubSignatureParseParamsMissingSecrets(t *testing.T) {
	p := GitHubSignatureAuth{}
	if _, err := p.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error for missing secrets")
	}
}

func TestGitHubSignatureRequiredParams(t *testing.T) {
	p := GitHubSignatureAuth{}
	if got := p.RequiredParams(); len(got) != 1 || got[0] != "secrets" {
		t.Fatalf("unexpected required params: %v", got)
	}
}

func TestGitHubSignatureMissingHeader(t *testing.T) {
	r := &http.Request{Header: http.Header{}, Body: io.NopCloser(strings.NewReader("body"))}
	p := GitHubSignatureAuth{}
	t.Setenv("SEC", "key")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}

func TestGitHubSignatureInvalidParams(t *testing.T) {
	r := &http.Request{Header: http.Header{"X-Hub-Signature-256": []string{"sig"}}, Body: io.NopCloser(strings.NewReader("body"))}
	p := GitHubSignatureAuth{}
	if p.Authenticate(context.Background(), r, nil) {
		t.Fatal("expected false for nil params")
	}
	if p.Authenticate(context.Background(), r, struct{}{}) {
		t.Fatal("expected false for wrong type")
	}
}

func TestGitHubSignatureCustomParamsAndSecretFallback(t *testing.T) {
	body := "abc"
	mac := hmac.New(sha256.New, []byte("good"))
	mac.Write([]byte(body))
	sig := "pre=" + hex.EncodeToString(mac.Sum(nil))

	hdr := http.Header{}
	hdr.Set("GH", sig)
	r := &http.Request{Header: hdr, Body: io.NopCloser(strings.NewReader(body))}

	p := GitHubSignatureAuth{}
	t.Setenv("GOOD", "good")
	cfg, err := p.ParseParams(map[string]interface{}{
		"secrets": []string{"env:BAD", "env:GOOD"},
		"header":  "GH",
		"prefix":  "pre=",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
}

func TestGitHubSignatureBodyError(t *testing.T) {
	r := &http.Request{Header: http.Header{"X-Hub-Signature-256": []string{"sig"}}, Body: errReadCloser{}}
	p := GitHubSignatureAuth{}
	t.Setenv("SEC", "key")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail on body error")
	}
}
