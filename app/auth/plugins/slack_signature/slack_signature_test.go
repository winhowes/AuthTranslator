package slacksignature

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
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

func TestSlackSignatureCustomParams(t *testing.T) {
	body := "abc"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	base := fmt.Sprintf("v1:%s:%s", ts, body)
	mac := hmac.New(sha256.New, []byte("good"))
	mac.Write([]byte(base))
	sig := "v1=" + hex.EncodeToString(mac.Sum(nil))

	hdr := http.Header{}
	hdr.Set("TS", ts)
	hdr.Set("SIGN", sig)
	r := &http.Request{Header: hdr, Body: io.NopCloser(strings.NewReader(body))}

	p := SlackSignatureAuth{}
	t.Setenv("BAD", "bad")
	t.Setenv("GOOD", "good")
	cfg, err := p.ParseParams(map[string]interface{}{
		"secrets":    []string{"env:BAD", "env:GOOD"},
		"version":    "v1",
		"sig_header": "SIGN",
		"ts_header":  "TS",
		"tolerance":  int64(60),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed with custom params")
	}
}

func TestAbs(t *testing.T) {
	if abs(5) != 5 || abs(-5) != 5 || abs(0) != 0 {
		t.Fatalf("abs basic cases failed")
	}
	if abs(math.MinInt64) != math.MaxInt64 {
		t.Fatalf("abs MinInt64 mismatch")
	}
}

func TestSlackSignatureMissingSig(t *testing.T) {
	body := "hi"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	r := &http.Request{Header: http.Header{
		"X-Slack-Request-Timestamp": []string{ts},
	}, Body: io.NopCloser(strings.NewReader(body))}
	p := SlackSignatureAuth{}
	t.Setenv("SEC", "k")
	cfg, _ := p.ParseParams(map[string]interface{}{"secrets": []string{"env:SEC"}})
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected auth to fail without signature header")
	}
}

func TestSlackSignatureWrongSecret(t *testing.T) {
	body := "msg"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	base := fmt.Sprintf("v0:%s:%s", ts, body)
	mac := hmac.New(sha256.New, []byte("good"))
	mac.Write([]byte(base))
	sig := "v0=" + hex.EncodeToString(mac.Sum(nil))
	r := &http.Request{Header: http.Header{
		"X-Slack-Request-Timestamp": []string{ts},
		"X-Slack-Signature":         []string{sig},
	}, Body: io.NopCloser(strings.NewReader(body))}
	p := SlackSignatureAuth{}
	t.Setenv("BAD", "bad")
	cfg, _ := p.ParseParams(map[string]interface{}{"secrets": []string{"env:BAD"}})
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected auth to fail with wrong secret")
	}
}
