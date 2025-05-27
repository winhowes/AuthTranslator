package outgoing

import (
	"net/http"

	"authtransformer/app/authplugins"
)

// TokenAuthOut adds a static token header to outbound requests.
type TokenAuthOut struct{}

func (t *TokenAuthOut) Name() string             { return "token" }
func (t *TokenAuthOut) RequiredParams() []string { return []string{"token", "header"} }

func (t *TokenAuthOut) AddAuth(r *http.Request, params map[string]string) {
	r.Header.Set(params["header"], params["token"])
}

func init() { authplugins.RegisterOutgoing(&TokenAuthOut{}) }
