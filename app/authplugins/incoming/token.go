package incoming

import (
	"net/http"
	"strings"

	"github.com/winhowes/AuthTransformer/app/authplugins"
)

// TokenAuth checks that the caller supplied the expected token.
type TokenAuth struct{}

func (t *TokenAuth) Name() string             { return "token" }
func (t *TokenAuth) RequiredParams() []string { return []string{"token", "header"} }
func (t *TokenAuth) OptionalParams() []string { return []string{"prefix"} }

func (t *TokenAuth) Authenticate(r *http.Request, params map[string]string) bool {
	header := params["header"]
	value := r.Header.Get(header)
	if prefix, ok := params["prefix"]; ok {
		value = strings.TrimPrefix(value, prefix)
	}
	return value == params["token"]
}

func init() { authplugins.RegisterIncoming(&TokenAuth{}) }
