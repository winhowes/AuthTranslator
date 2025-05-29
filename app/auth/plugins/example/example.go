//go:build example

package example

import (
	"context"
	"net/http"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
)

// Incoming example plugin that allows all requests.
type incoming struct{}

func (incoming) Name() string                                                  { return "example" }
func (incoming) RequiredParams() []string                                      { return nil }
func (incoming) OptionalParams() []string                                      { return nil }
func (incoming) ParseParams(map[string]interface{}) (interface{}, error)       { return struct{}{}, nil }
func (incoming) Authenticate(context.Context, *http.Request, interface{}) bool { return true }

func init() { authplugins.RegisterIncoming(&incoming{}) }
