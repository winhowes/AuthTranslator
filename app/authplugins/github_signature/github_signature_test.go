package githubsignature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	if !p.Authenticate(r, cfg) {
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
	if p.Authenticate(r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}

func TestGitHubSignatureOptionalParams(t *testing.T) {
	p := GitHubSignatureAuth{}
	if got := p.OptionalParams(); len(got) != 2 || got[0] != "header" {
		t.Fatalf("unexpected optional params: %v", got)
	}
}
