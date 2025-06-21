package authplugins

import (
	"context"
	"net/http"
	"testing"
)

// minimal incoming plugin
type testIncoming struct{ name string }

func (p testIncoming) Name() string                                                { return p.name }
func (testIncoming) ParseParams(map[string]interface{}) (interface{}, error)       { return nil, nil }
func (testIncoming) Authenticate(context.Context, *http.Request, interface{}) bool { return true }
func (testIncoming) RequiredParams() []string                                      { return nil }
func (testIncoming) OptionalParams() []string                                      { return nil }

// minimal outgoing plugin
type testOutgoing struct{ name string }

func (p testOutgoing) Name() string                                            { return p.name }
func (testOutgoing) ParseParams(map[string]interface{}) (interface{}, error)   { return nil, nil }
func (testOutgoing) AddAuth(context.Context, *http.Request, interface{}) error { return nil }
func (testOutgoing) RequiredParams() []string                                  { return nil }
func (testOutgoing) OptionalParams() []string                                  { return nil }

func TestRegistryIncomingOutgoing(t *testing.T) {
	// Save original registries and restore after test
	inOrig := incomingRegistry
	outOrig := outgoingRegistry
	t.Cleanup(func() {
		incomingRegistry = inOrig
		outgoingRegistry = outOrig
	})

	// reset registries
	incomingRegistry = map[string]IncomingAuthPlugin{}
	outgoingRegistry = map[string]OutgoingAuthPlugin{}

	in := testIncoming{name: "in"}
	out := testOutgoing{name: "out"}

	RegisterIncoming(in)
	RegisterOutgoing(out)

	if got := GetIncoming("in"); got == nil {
		t.Fatal("expected incoming plugin returned")
	}
	if got := GetOutgoing("out"); got == nil {
		t.Fatal("expected outgoing plugin returned")
	}
	if GetIncoming("missing") != nil {
		t.Fatal("expected nil for unknown incoming plugin")
	}
	if GetOutgoing("missing") != nil {
		t.Fatal("expected nil for unknown outgoing plugin")
	}
}
