package passthrough

import (
	"context"
	"net/http"

	"github.com/winhowes/AuthTranslator/app/auth"
)

// PassThruAuth accepts every request without modifying it.
type PassThruAuth struct{}

func (p *PassThruAuth) Name() string             { return "passthrough" }
func (p *PassThruAuth) RequiredParams() []string { return nil }
func (p *PassThruAuth) OptionalParams() []string { return nil }

func (p *PassThruAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
	// Disallow unknown fields even though we don't expect any parameters.
	_, err := authplugins.ParseParams[struct{}](m)
	if err != nil {
		return nil, err
	}
	return struct{}{}, nil
}

func (p *PassThruAuth) Authenticate(ctx context.Context, r *http.Request, _ interface{}) bool {
	return true
}

func init() { authplugins.RegisterIncoming(&PassThruAuth{}) }
