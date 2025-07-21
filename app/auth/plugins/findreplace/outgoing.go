package findreplace

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

// outParams configures the find and replace plugin.
type outParams struct {
	FindSecret    string `json:"find_secret"`
	ReplaceSecret string `json:"replace_secret"`
}

type FindReplace struct{}

func (f *FindReplace) Name() string             { return "find_replace" }
func (f *FindReplace) RequiredParams() []string { return []string{"find_secret", "replace_secret"} }
func (f *FindReplace) OptionalParams() []string { return nil }

func (f *FindReplace) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[outParams](m)
	if err != nil {
		return nil, err
	}
	if p.FindSecret == "" || p.ReplaceSecret == "" {
		return nil, fmt.Errorf("missing secrets")
	}
	return p, nil
}

func replaceAll(s, find, repl string) string {
	if strings.Contains(s, find) {
		return strings.ReplaceAll(s, find, repl)
	}
	return s
}

func (f *FindReplace) AddAuth(ctx context.Context, r *http.Request, params interface{}) error {
	cfg, ok := params.(*outParams)
	if !ok || cfg.FindSecret == "" || cfg.ReplaceSecret == "" {
		return fmt.Errorf("invalid config")
	}
	findVal, err := secrets.LoadSecret(ctx, cfg.FindSecret)
	if err != nil {
		return err
	}
	replVal, err := secrets.LoadSecret(ctx, cfg.ReplaceSecret)
	if err != nil {
		return err
	}

	// URL components
	r.URL.Scheme = replaceAll(r.URL.Scheme, findVal, replVal)
	r.URL.Host = replaceAll(r.URL.Host, findVal, replVal)
	r.Host = replaceAll(r.Host, findVal, replVal)
	r.URL.Path = replaceAll(r.URL.Path, findVal, replVal)
	if r.URL.RawPath != "" {
		r.URL.RawPath = replaceAll(r.URL.RawPath, findVal, replVal)
	}
	r.URL.RawQuery = replaceAll(r.URL.RawQuery, findVal, replVal)
	r.RequestURI = r.URL.RequestURI()

	// Headers
	newHeader := http.Header{}
	for k, vals := range r.Header {
		nk := replaceAll(k, findVal, replVal)
		for _, v := range vals {
			newHeader.Add(nk, replaceAll(v, findVal, replVal))
		}
	}
	r.Header = newHeader

	// Body
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		_ = r.Body.Close()
		nb := replaceAll(string(b), findVal, replVal)
		r.Body = io.NopCloser(bytes.NewBufferString(nb))
		r.ContentLength = int64(len(nb))
	}

	return nil
}

func init() { authplugins.RegisterOutgoing(&FindReplace{}) }
