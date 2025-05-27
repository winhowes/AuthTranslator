package urlpath

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/winhowes/AuthTranslator/app/authplugins"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

// inParams configures URL path secret validation.
type inParams struct {
	Secrets []string `json:"secrets"`
}

type URLPathAuth struct{}

func (u *URLPathAuth) Name() string             { return "url_path" }
func (u *URLPathAuth) RequiredParams() []string { return []string{"secrets"} }
func (u *URLPathAuth) OptionalParams() []string { return nil }

func (u *URLPathAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[inParams](m)
	if err != nil {
		return nil, err
	}
	if len(p.Secrets) == 0 {
		return nil, fmt.Errorf("missing secrets")
	}
	return p, nil
}

func (u *URLPathAuth) Authenticate(r *http.Request, p interface{}) bool {
	cfg, ok := p.(*inParams)
	if !ok {
		return false
	}
	for _, ref := range cfg.Secrets {
		sec, err := secrets.LoadSecret(ref)
		if err != nil {
			continue
		}
		suffix := "/" + sec
		if strings.HasSuffix(r.URL.Path, suffix) {
			r.URL.Path = strings.TrimSuffix(r.URL.Path, suffix)
			r.RequestURI = r.URL.RequestURI()
			return true
		}
	}
	return false
}

func init() { authplugins.RegisterIncoming(&URLPathAuth{}) }
