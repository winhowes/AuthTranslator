package main

import (
	"testing"

	_ "github.com/winhowes/AuthTransformer/app/authplugins/incoming"
	_ "github.com/winhowes/AuthTransformer/app/authplugins/outgoing"
)

func TestAddIntegrationMissingParam(t *testing.T) {
	i := &Integration{
		Name:         "test",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{}}},
	}
	if err := AddIntegration(i); err == nil {
		t.Fatal("expected error for missing params")
	}
}

func TestAddIntegrationValid(t *testing.T) {
	i := &Integration{
		Name:         "testvalid",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "X-Auth"}}},
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddIntegrationOptionalParam(t *testing.T) {
	i := &Integration{
		Name:         "testoptional",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]string{"token": "x", "header": "X-Auth", "prefix": "Bearer "}}},
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddIntegrationUnknownParam(t *testing.T) {
	i := &Integration{
		Name:         "testunknown",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]string{"token": "x", "header": "X-Auth", "bogus": "y"}}},
	}
	if err := AddIntegration(i); err == nil {
		t.Fatal("expected error for unknown param")
	}
}
