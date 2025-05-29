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

	"github.com/winhowes/AuthTranslator/app/secrets"
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
func TestGitHubSignatureParseParamsDefaultsAndError(t *testing.T) {
	p := GitHubSignatureAuth{}
	t.Setenv("S", "k")
	cfgI, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:S"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok := cfgI.(*githubSigParams)
	if !ok || cfg.Header != "X-Hub-Signature-256" || cfg.Prefix != "sha256=" {
		t.Fatalf("unexpected cfg %+v", cfgI)
	}
	if _, err := p.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error for missing secrets")
	}
}

type failPlugin struct{}

func (failPlugin) Prefix() string                               { return "fail" }
func (failPlugin) Load(context.Context, string) (string, error) { return "", errors.New("fail") }

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("err") }
func (errReadCloser) Close() error             { return nil }

func TestGitHubSignatureAuthEdgeCases(t *testing.T) {
	secrets.Register(failPlugin{})
	body := "hello"
	mac := hmac.New(sha256.New, []byte("key"))
	mac.Write([]byte(body))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	p := GitHubSignatureAuth{}
	t.Setenv("GOOD", "key")
	cfg, _ := p.ParseParams(map[string]interface{}{"secrets": []string{"env:GOOD"}})

	// body read error
	r := &http.Request{Header: http.Header{"X-Hub-Signature-256": []string{sig}}, Body: errReadCloser{}}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected failure on body read error")
	}

	// missing header
	r = &http.Request{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected failure with missing header")
	}

	// secret error then success
	cfg2, _ := p.ParseParams(map[string]interface{}{"secrets": []string{"fail:oops", "env:GOOD"}})
	r = &http.Request{Header: http.Header{"X-Hub-Signature-256": []string{sig}}, Body: io.NopCloser(strings.NewReader(body))}
	if !p.Authenticate(context.Background(), r, cfg2) {
		t.Fatal("expected success with second secret")
	}
}
