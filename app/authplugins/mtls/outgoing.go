package mtls

import (
	"fmt"
	"net/http"

	"github.com/winhowes/AuthTranslator/app/authplugins"
)

// outParams holds outbound mTLS configuration. Currently unused beyond validation.
type outParams struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type MTLSAuthOut struct{}

func (m *MTLSAuthOut) Name() string             { return "mtls" }
func (m *MTLSAuthOut) RequiredParams() []string { return []string{"cert", "key"} }
func (m *MTLSAuthOut) OptionalParams() []string { return nil }

func (m *MTLSAuthOut) ParseParams(mp map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[outParams](mp)
	if err != nil {
		return nil, err
	}
	if p.Cert == "" || p.Key == "" {
		return nil, fmt.Errorf("missing cert or key")
	}
	return p, nil
}

// AddAuth currently performs no per-request actions for mTLS.
func (m *MTLSAuthOut) AddAuth(r *http.Request, p interface{}) {}

func init() { authplugins.RegisterOutgoing(&MTLSAuthOut{}) }
