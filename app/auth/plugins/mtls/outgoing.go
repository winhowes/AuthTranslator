package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/winhowes/AuthTranslator/app/auth"
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
	certPEM, err := secrets.LoadSecret(context.Background(), p.Cert)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	keyPEM, err := secrets.LoadSecret(context.Background(), p.Key)
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

// AddAuth exposes the configured client certificate's common name to the backend
// via the "X-TLS-Client-CN" header. This allows upstream services to easily
// identify the client certificate used for the mTLS connection.
func (m *MTLSAuthOut) AddAuth(ctx context.Context, r *http.Request, p interface{}) {
	cfg, ok := p.(*outParams)
	if !ok || cfg.transport == nil || cfg.transport.TLSClientConfig == nil {
		return
	}
	if len(cfg.transport.TLSClientConfig.Certificates) == 0 || len(cfg.transport.TLSClientConfig.Certificates[0].Certificate) == 0 {
		return
	}
	cert, err := x509.ParseCertificate(cfg.transport.TLSClientConfig.Certificates[0].Certificate[0])
	if err != nil {
		return
	}
	r.Header.Set("X-TLS-Client-CN", cert.Subject.CommonName)
}

// Transport exposes the configured mTLS transport for integration usage.
func (m *MTLSAuthOut) Transport(p interface{}) *http.Transport {
	cfg, ok := p.(*outParams)
	if !ok {
		return nil
	}
	return cfg.transport
}

func init() { authplugins.RegisterOutgoing(&MTLSAuthOut{}) }
