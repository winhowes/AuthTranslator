package urlpath

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/winhowes/AuthTransformer/app/authplugins"
	"github.com/winhowes/AuthTransformer/app/secrets"
)

// outParams configures URL path secret attachment.
type outParams struct {
	Secrets []string `json:"secrets"`
}

type URLPathAuthOut struct{}

func (u *URLPathAuthOut) Name() string             { return "url_path" }
func (u *URLPathAuthOut) RequiredParams() []string { return []string{"secrets"} }
func (u *URLPathAuthOut) OptionalParams() []string { return nil }

func (u *URLPathAuthOut) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[outParams](m)
	if err != nil {
		return nil, err
	}
	if len(p.Secrets) == 0 {
		return nil, fmt.Errorf("missing secrets")
	}
	return p, nil
}

func (u *URLPathAuthOut) AddAuth(r *http.Request, p interface{}) {
	cfg, ok := p.(*outParams)
	if !ok || len(cfg.Secrets) == 0 {
		return
	}
	sec, err := secrets.LoadRandomSecret(cfg.Secrets)
	if err != nil {
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/") {
		r.URL.Path += "/" + sec
	} else {
		r.URL.Path += sec
	}
	r.RequestURI = r.URL.RequestURI()
}

func init() { authplugins.RegisterOutgoing(&URLPathAuthOut{}) }
