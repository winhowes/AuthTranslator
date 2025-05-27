package authplugins

import "net/http"

// IncomingAuthPlugin processes authentication from incoming callers.
type IncomingAuthPlugin interface {
	Name() string
	RequiredParams() []string
	Authenticate(r *http.Request, params map[string]string) bool
}

// OutgoingAuthPlugin applies authentication to outbound requests.
type OutgoingAuthPlugin interface {
	Name() string
	RequiredParams() []string
	AddAuth(r *http.Request, params map[string]string)
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
