package passthrough

import (
	"context"
	"net/http"

	"github.com/winhowes/AuthTranslator/app/auth"
)

// PassThruAuthOut performs no modification to the request.
type PassThruAuthOut struct{}

func (p *PassThruAuthOut) Name() string             { return "passthrough" }
func (p *PassThruAuthOut) RequiredParams() []string { return nil }
func (p *PassThruAuthOut) OptionalParams() []string { return nil }

func (p *PassThruAuthOut) ParseParams(m map[string]interface{}) (interface{}, error) {
	// Disallow unknown fields even though we don't expect any parameters.
	_, err := authplugins.ParseParams[struct{}](m)
	if err != nil {
		return nil, err
	}
	return struct{}{}, nil
}

func (p *PassThruAuthOut) AddAuth(ctx context.Context, r *http.Request, _ interface{}) error {
	// No-op
	return nil
}

func init() { authplugins.RegisterOutgoing(&PassThruAuthOut{}) }
