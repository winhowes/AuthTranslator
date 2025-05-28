package main

import (
	"testing"
	"time"

	_ "github.com/winhowes/AuthTranslator/app/authplugins/basic"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/google_oidc"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/token"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
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
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})
}

func TestAddIntegrationOptionalParam(t *testing.T) {
	i := &Integration{
		Name:         "testoptional",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{"secrets": []string{"env:TOK"}, "header": "X-Auth", "prefix": "Bearer "}}},
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})
}

func TestAddIntegrationUnknownParam(t *testing.T) {
	i := &Integration{
		Name:         "testunknown",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{"secrets": []string{"x"}, "header": "X-Auth", "bogus": "y"}}},
	}
	if err := AddIntegration(i); err == nil {
		t.Fatal("expected error for unknown param")
	}
}

func TestAddIntegrationInvalidDestination(t *testing.T) {
	i := &Integration{
		Name:         "badurl",
		Destination:  "://bad url",
		InRateLimit:  1,
		OutRateLimit: 1,
	}
	if err := AddIntegration(i); err == nil {
		t.Fatal("expected error for invalid destination")
	}
}

func TestAddIntegrationDuplicateName(t *testing.T) {
	i := &Integration{
		Name:         "testduplicate",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})
	if err := AddIntegration(i); err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestGetIntegrationCaseInsensitive(t *testing.T) {
	i := &Integration{
		Name:         "MiXeD",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})

	if _, ok := GetIntegration("mixed"); !ok {
		t.Fatal("lookup by lowercase failed")
	}
	if _, ok := GetIntegration("MIXED"); !ok {
		t.Fatal("lookup by uppercase failed")
	}
}

func TestUpdateIntegration(t *testing.T) {
	i := &Integration{
		Name:         "update",
		Destination:  "http://a.com",
		InRateLimit:  1,
		OutRateLimit: 1,
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	updated := &Integration{
		Name:         "update",
		Destination:  "http://b.com",
		InRateLimit:  2,
		OutRateLimit: 2,
	}
	if err := UpdateIntegration(updated); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, ok := GetIntegration("update")
	if !ok || got.destinationURL.String() != "http://b.com" {
		t.Fatalf("integration not updated")
	}
	t.Cleanup(func() {
		got.inLimiter.Stop()
		got.outLimiter.Stop()
	})
}

func TestDeleteIntegration(t *testing.T) {
	i := &Integration{
		Name:        "delete",
		Destination: "http://c.com",
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	DeleteIntegration("delete")
	if _, ok := GetIntegration("delete"); ok {
		t.Fatalf("integration not deleted")
	}
}

func TestIntegrationRateLimitWindow(t *testing.T) {
	i := &Integration{
		Name:            "window",
		Destination:     "http://example.com",
		InRateLimit:     1,
		OutRateLimit:    1,
		RateLimitWindow: "10ms",
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})

	if !i.inLimiter.Allow("a") {
		t.Fatal("first call not allowed")
	}
	if i.inLimiter.Allow("a") {
		t.Fatal("limit should be enforced")
	}
	time.Sleep(15 * time.Millisecond)
	if !i.inLimiter.Allow("a") {
		t.Fatal("limit did not reset after window")
	}
}

func TestIntegrationInvalidWindow(t *testing.T) {
	i := &Integration{
		Name:            "badwindow",
		Destination:     "http://example.com",
		InRateLimit:     1,
		OutRateLimit:    1,
		RateLimitWindow: "0",
	}
	if err := AddIntegration(i); err == nil {
		t.Fatal("expected error for non-positive window")
	}
}
