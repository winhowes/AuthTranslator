package mtls

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/winhowes/AuthTranslator/app/authplugins"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

// outParams holds outbound mTLS configuration. Currently unused beyond validation.
type outParams struct {
	Cert      string          `json:"cert"`
	Key       string          `json:"key"`
	transport *http.Transport `json:"-"`
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
	certPEM, err := secrets.LoadSecret(p.Cert)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	keyPEM, err := secrets.LoadSecret(p.Key)
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}
	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("tls pair: %w", err)
	}
	p.transport = &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}}}
	return p, nil
}

// AddAuth currently performs no per-request actions for mTLS.
func (m *MTLSAuthOut) AddAuth(r *http.Request, p interface{}) {}

// Transport exposes the configured mTLS transport for integration usage.
func (m *MTLSAuthOut) Transport(p interface{}) *http.Transport {
	cfg, ok := p.(*outParams)
	if !ok {
		return nil
	}
	return cfg.transport
}

func init() { authplugins.RegisterOutgoing(&MTLSAuthOut{}) }
