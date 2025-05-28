//go:build example

package example

import (
	"github.com/winhowes/AuthTranslator/app/authplugins"
	"net/http"
)

// Incoming example plugin that allows all requests.
type incoming struct{}

func (incoming) RequiredParams() []string                                    { return nil }
func (incoming) OptionalParams() []string                                    { return nil }
func (incoming) ParseParams(map[string]interface{}) (interface{}, error)     { return struct{}{}, nil }
func (incoming) Authenticate(_ interface{}, _ *http.Request) (string, error) { return "", nil }

func init() { authplugins.RegisterIncoming("example", incoming{}) }
