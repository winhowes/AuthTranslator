package mtls

import (
	"context"
	"net/http"

	"github.com/winhowes/AuthTranslator/app/auth"
)

// mtlsParams defines allowed subject names for client certificates.
type mtlsParams struct {
	Subjects []string `json:"subjects"`
}

type MTLSAuth struct{}

func (m *MTLSAuth) Name() string             { return "mtls" }
func (m *MTLSAuth) RequiredParams() []string { return []string{} }
func (m *MTLSAuth) OptionalParams() []string { return []string{"subjects"} }

func (m *MTLSAuth) ParseParams(data map[string]interface{}) (interface{}, error) {
	return authplugins.ParseParams[mtlsParams](data)
}

func (m *MTLSAuth) Authenticate(ctx context.Context, r *http.Request, p interface{}) bool {
	cfg, ok := p.(*mtlsParams)
	if !ok {
		return false
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return false
	}
	if len(cfg.Subjects) == 0 {
		return true
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	subj := r.TLS.PeerCertificates[0].Subject.CommonName
	for _, s := range cfg.Subjects {
		if subj == s {
			return true
		}
	}
	return false
}

func (m *MTLSAuth) Identify(r *http.Request, p interface{}) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName, true
}

func init() { authplugins.RegisterIncoming(&MTLSAuth{}) }
