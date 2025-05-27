package outgoing

import (
	"net/http"

	"github.com/winhowes/AuthTransformer/app/authplugins"
)

// TokenAuthOut adds a static token header to outbound requests.
type TokenAuthOut struct{}

func (t *TokenAuthOut) Name() string             { return "token" }
func (t *TokenAuthOut) RequiredParams() []string { return []string{"token", "header"} }
func (t *TokenAuthOut) OptionalParams() []string { return []string{"prefix"} }

func (t *TokenAuthOut) AddAuth(r *http.Request, params map[string]string) {
	token := params["token"]
	if prefix, ok := params["prefix"]; ok {
		token = prefix + token
	}
	r.Header.Set(params["header"], token)
}

func init() { authplugins.RegisterOutgoing(&TokenAuthOut{}) }
