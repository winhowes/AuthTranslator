package authplugins

import (
	"context"
	"net/http"
)

// IncomingAuthPlugin processes authentication from incoming callers.
// ParseParams should validate and convert the raw parameter map into a
// plugin-specific configuration struct.
type IncomingAuthPlugin interface {
	Name() string
	ParseParams(map[string]interface{}) (interface{}, error)
	Authenticate(ctx context.Context, r *http.Request, params interface{}) bool
	RequiredParams() []string
	OptionalParams() []string
}

// Identifier is implemented by incoming auth plugins that can derive a caller
// identifier from the request. The identifier is used by allowlist checks.
type Identifier interface {
	Identify(r *http.Request, params interface{}) (string, bool)
}

// AuthStripper is optionally implemented by incoming auth plugins that wish to
// remove authentication data from the request after it has been verified.
// The proxy calls this after calling Identify.
type AuthStripper interface {
	StripAuth(r *http.Request, params interface{})
}

// OutgoingAuthPlugin applies authentication to outbound requests.
type OutgoingAuthPlugin interface {
	Name() string
	ParseParams(map[string]interface{}) (interface{}, error)
	AddAuth(ctx context.Context, r *http.Request, params interface{})
	RequiredParams() []string
	OptionalParams() []string
}

var incomingRegistry = map[string]IncomingAuthPlugin{}
var outgoingRegistry = map[string]OutgoingAuthPlugin{}

// RegisterIncoming registers an incoming auth plugin.
func RegisterIncoming(p IncomingAuthPlugin) { incomingRegistry[p.Name()] = p }

// RegisterOutgoing registers an outgoing auth plugin.
func RegisterOutgoing(p OutgoingAuthPlugin) { outgoingRegistry[p.Name()] = p }

// GetIncoming retrieves an incoming auth plugin by name.
func GetIncoming(name string) IncomingAuthPlugin { return incomingRegistry[name] }

// GetOutgoing retrieves an outgoing auth plugin by name.
func GetOutgoing(name string) OutgoingAuthPlugin { return outgoingRegistry[name] }
