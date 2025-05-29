package slacksignature

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestSlackSignatureAuth(t *testing.T) {
	body := "hello"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	base := fmt.Sprintf("v0:%s:%s", ts, body)
	mac := hmac.New(sha256.New, []byte("key"))
	mac.Write([]byte(base))
	sig := "v0=" + hex.EncodeToString(mac.Sum(nil))

	r := &http.Request{Header: http.Header{
		"X-Slack-Request-Timestamp": []string{ts},
		"X-Slack-Signature":         []string{sig},
	}, Body: io.NopCloser(strings.NewReader(body))}

	p := SlackSignatureAuth{}
	t.Setenv("SEC", "key")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
}

func TestSlackSignatureAuthOldTimestamp(t *testing.T) {
	body := "hello"
	ts := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	base := fmt.Sprintf("v0:%s:%s", ts, body)
	mac := hmac.New(sha256.New, []byte("key"))
	mac.Write([]byte(base))
	sig := "v0=" + hex.EncodeToString(mac.Sum(nil))

	r := &http.Request{Header: http.Header{
		"X-Slack-Request-Timestamp": []string{ts},
		"X-Slack-Signature":         []string{sig},
	}, Body: io.NopCloser(strings.NewReader(body))}

	p := SlackSignatureAuth{}
	t.Setenv("SEC", "key")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}

func TestSlackSignatureAuthBadTimestamp(t *testing.T) {
	r := &http.Request{Header: http.Header{
		"X-Slack-Request-Timestamp": []string{"notanint"},
		"X-Slack-Signature":         []string{"v0=abc"},
	}, Body: io.NopCloser(strings.NewReader(""))}

	p := SlackSignatureAuth{}
	t.Setenv("SEC", "key")
	cfg, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail")
	}
}

func TestSlackSignatureDefaults(t *testing.T) {
	p := SlackSignatureAuth{}
	t.Setenv("SEC", "key")
	cfgI, err := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok := cfgI.(*slackSigParams)
	if !ok {
		t.Fatalf("unexpected config type %T", cfgI)
	}
	if cfg.Version != "v0" || cfg.SigHeader != "X-Slack-Signature" || cfg.TimestampHeader != "X-Slack-Request-Timestamp" || cfg.Tolerance != 300 {
		t.Fatalf("unexpected defaults %+v", cfg)
	}
}

func TestSlackSignatureOptionalParams(t *testing.T) {
	p := SlackSignatureAuth{}
	if got := p.OptionalParams(); len(got) != 4 || got[0] != "version" {
		t.Fatalf("unexpected optional params: %v", got)
	}
}
