package authplugins

import "net/http"

// IncomingAuthPlugin processes authentication from incoming callers.
// IncomingAuthPlugin processes authentication from incoming callers.
// ParseParams should validate and convert the raw parameter map into a
// plugin-specific configuration struct.
type IncomingAuthPlugin interface {
	Name() string
	ParseParams(map[string]interface{}) (interface{}, error)
	Authenticate(r *http.Request, params interface{}) bool
}

// OutgoingAuthPlugin applies authentication to outbound requests.
// OutgoingAuthPlugin applies authentication to outbound requests.
type OutgoingAuthPlugin interface {
	Name() string
	ParseParams(map[string]interface{}) (interface{}, error)
	AddAuth(r *http.Request, params interface{})
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
