package slacksignature

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/winhowes/AuthTranslator/app/auth"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

// slackSigParams holds config for Slack signature validation.
type slackSigParams struct {
	Secrets         []string `json:"secrets"`
	Version         string   `json:"version"`
	SigHeader       string   `json:"sig_header"`
	TimestampHeader string   `json:"ts_header"`
	Tolerance       int64    `json:"tolerance"`
}

type SlackSignatureAuth struct{}

func (s *SlackSignatureAuth) Name() string { return "slack_signature" }

func (s *SlackSignatureAuth) RequiredParams() []string { return []string{"secrets"} }

func (s *SlackSignatureAuth) OptionalParams() []string {
	return []string{"version", "sig_header", "ts_header", "tolerance"}
}

func (s *SlackSignatureAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[slackSigParams](m)
	if err != nil {
		return nil, err
	}
	if len(p.Secrets) == 0 {
		return nil, fmt.Errorf("missing secrets")
	}
	if p.Version == "" {
		p.Version = "v0"
	}
	if p.SigHeader == "" {
		p.SigHeader = "X-Slack-Signature"
	}
	if p.TimestampHeader == "" {
		p.TimestampHeader = "X-Slack-Request-Timestamp"
	}
	if p.Tolerance == 0 {
		p.Tolerance = 300
	}
	return p, nil
}

func (s *SlackSignatureAuth) Authenticate(ctx context.Context, r *http.Request, p interface{}) bool {
	cfg, ok := p.(*slackSigParams)
	if !ok {
		return false
	}
	tsStr := r.Header.Get(cfg.TimestampHeader)
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	if abs(time.Now().Unix()-ts) > cfg.Tolerance {
		return false
	}
	body, err := authplugins.GetBody(r)
	if err != nil {
		return false
	}
	base := fmt.Sprintf("%s:%s:%s", cfg.Version, tsStr, string(body))
	sig := r.Header.Get(cfg.SigHeader)
	if sig == "" {
		return false
	}
	for _, ref := range cfg.Secrets {
		secret, err := secrets.LoadSecret(ctx, ref)
		if err != nil {
			continue
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(base))
		expected := cfg.Version + "=" + hex.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(expected), []byte(sig)) {
			return true
		}
	}
	return false
}

func abs(i int64) int64 {
	if i < 0 {
		if i == math.MinInt64 {
			return math.MaxInt64
		}
		return -i
	}
	return i
}

func init() { authplugins.RegisterIncoming(&SlackSignatureAuth{}) }
