package incoming

import (
	"net/http"

	"authtransformer/app/authplugins"
)

// TokenAuth checks that the caller supplied the expected token.
type TokenAuth struct{}

func (t *TokenAuth) Name() string             { return "token" }
func (t *TokenAuth) RequiredParams() []string { return []string{"token", "header"} }

func (t *TokenAuth) Authenticate(r *http.Request, params map[string]string) bool {
	header := params["header"]
	return r.Header.Get(header) == params["token"]
}

func init() { authplugins.RegisterIncoming(&TokenAuth{}) }
