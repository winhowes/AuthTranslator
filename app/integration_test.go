package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/basic"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/google_oidc"
	mtls "github.com/winhowes/AuthTranslator/app/auth/plugins/mtls"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/token"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

type outgoingTransportPlugin struct {
	transport *http.Transport
}

func (o *outgoingTransportPlugin) Name() string { return "testtransport" }
func (o *outgoingTransportPlugin) ParseParams(map[string]interface{}) (interface{}, error) {
	return struct{}{}, nil
}
func (o *outgoingTransportPlugin) AddAuth(ctx context.Context, r *http.Request, params interface{}) error {
	return nil
}
func (o *outgoingTransportPlugin) RequiredParams() []string              { return nil }
func (o *outgoingTransportPlugin) OptionalParams() []string              { return nil }
func (o *outgoingTransportPlugin) Transport(interface{}) *http.Transport { return o.transport }

type failingIncomingPlugin struct{}

func (f failingIncomingPlugin) Name() string { return "failing-incoming" }
func (f failingIncomingPlugin) ParseParams(map[string]interface{}) (interface{}, error) {
	return struct{ Missing string }{}, nil
}
func (f failingIncomingPlugin) Authenticate(ctx context.Context, r *http.Request, params interface{}) bool {
	return true
}
func (f failingIncomingPlugin) RequiredParams() []string { return []string{"missing"} }
func (f failingIncomingPlugin) OptionalParams() []string { return nil }

type failingOutgoingPlugin struct{}

func (f failingOutgoingPlugin) Name() string { return "failing-outgoing" }
func (f failingOutgoingPlugin) ParseParams(map[string]interface{}) (interface{}, error) {
	return nil, errors.New("parse failure")
}
func (f failingOutgoingPlugin) AddAuth(ctx context.Context, r *http.Request, params interface{}) error {
	return nil
}
func (f failingOutgoingPlugin) RequiredParams() []string { return nil }
func (f failingOutgoingPlugin) OptionalParams() []string { return nil }

type missingFieldOutgoingPlugin struct{}

func (m missingFieldOutgoingPlugin) Name() string { return "missing-field-out" }
func (m missingFieldOutgoingPlugin) ParseParams(map[string]interface{}) (interface{}, error) {
	return struct{}{}, nil
}
func (m missingFieldOutgoingPlugin) AddAuth(ctx context.Context, r *http.Request, params interface{}) error {
	return nil
}
func (m missingFieldOutgoingPlugin) RequiredParams() []string { return []string{"needed"} }
func (m missingFieldOutgoingPlugin) OptionalParams() []string { return nil }

type secretFailOutgoingPlugin struct{}

func (s secretFailOutgoingPlugin) Name() string { return "secret-fail-out" }
func (s secretFailOutgoingPlugin) ParseParams(map[string]interface{}) (interface{}, error) {
	return struct {
		Secrets []string `json:"secrets"`
	}{Secrets: []string{"bogus:VAL"}}, nil
}
func (s secretFailOutgoingPlugin) AddAuth(ctx context.Context, r *http.Request, params interface{}) error {
	return nil
}
func (s secretFailOutgoingPlugin) RequiredParams() []string { return nil }
func (s secretFailOutgoingPlugin) OptionalParams() []string { return nil }

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

func TestAddIntegrationInvalidName(t *testing.T) {
	i := &Integration{
		Name:        "bad|name",
		Destination: "http://example.com",
	}
	if err := AddIntegration(i); err == nil || !strings.Contains(err.Error(), "invalid integration name") {
		t.Fatalf("expected invalid name error, got %v", err)
	}
}

func TestAddIntegrationAllowsDotsAndUnderscores(t *testing.T) {
	i := &Integration{
		Name:         "with.dot_and-name",
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

func TestUpdateIntegrationCreatesNew(t *testing.T) {
	updated := &Integration{
		Name:         "update-new",
		Destination:  "http://c.com",
		InRateLimit:  1,
		OutRateLimit: 2,
	}
	if err := UpdateIntegration(updated); err != nil {
		t.Fatalf("update new: %v", err)
	}
	got, ok := GetIntegration("update-new")
	if !ok {
		t.Fatalf("integration not created via update")
	}
	t.Cleanup(func() {
		got.inLimiter.Stop()
		got.outLimiter.Stop()
		DeleteIntegration("update-new")
	})
	if got.inLimiter == nil || got.outLimiter == nil {
		t.Fatalf("rate limiters not initialized")
	}
}

func TestResolveRequestDestinationWildcard(t *testing.T) {
	integ := &Integration{Name: "wild", Destination: "https://*.example.com/base"}
	if err := prepareIntegration(integ); err != nil {
		t.Fatalf("prepareIntegration: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://wild.local/request", nil)
	req.Header.Set("X-AT-Destination", "https://foo.example.com")

	dest, err := integ.resolveRequestDestination(req)
	if err != nil {
		t.Fatalf("resolveRequestDestination: %v", err)
	}
	if dest.Host != "foo.example.com" {
		t.Fatalf("unexpected host: %s", dest.Host)
	}
	if dest.Path != "/base" {
		t.Fatalf("unexpected path: %s", dest.Path)
	}
	if dest.Scheme != "https" {
		t.Fatalf("unexpected scheme: %s", dest.Scheme)
	}
}

func TestResolveRequestDestinationWildcardNoScheme(t *testing.T) {
	integ := &Integration{Name: "wild-noscheme", Destination: "https://*.example.com"}
	if err := prepareIntegration(integ); err != nil {
		t.Fatalf("prepareIntegration: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://wild-noscheme", nil)
	req.Header.Set("X-AT-Destination", "//foo.example.com")

	dest, err := integ.resolveRequestDestination(req)
	if err != nil {
		t.Fatalf("resolveRequestDestination: %v", err)
	}
	if dest.Scheme != "https" {
		t.Fatalf("expected scheme fallback to https, got %s", dest.Scheme)
	}
	if dest.Host != "foo.example.com" {
		t.Fatalf("unexpected host: %s", dest.Host)
	}
}

func TestResolveRequestDestinationWildcardErrors(t *testing.T) {
	integ := &Integration{Name: "wild-err", Destination: "https://*.example.com"}
	if err := prepareIntegration(integ); err != nil {
		t.Fatalf("prepareIntegration: %v", err)
	}

	tests := []struct {
		name   string
		header string
	}{
		{name: "missing", header: ""},
		{name: "no_subdomain", header: "https://example.com"},
		{name: "wrong_domain", header: "https://foo.notexample.com"},
		{name: "bad_scheme", header: "http://foo.example.com"},
		{name: "unexpected_port", header: "https://foo.example.com:8080"},
		{name: "user_info", header: "https://user:pass@foo.example.com"},
		{name: "missing_host", header: "https:///path"},
		{name: "wildcard_header", header: "https://*.example.com"},
		{name: "invalid_url", header: "%"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://wild-err", nil)
			if tc.header != "" {
				req.Header.Set("X-AT-Destination", tc.header)
			}
			if _, err := integ.resolveRequestDestination(req); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestResolveRequestDestinationWildcardPort(t *testing.T) {
	integ := &Integration{Name: "wild-port", Destination: "https://*.example.com:8443"}
	if err := prepareIntegration(integ); err != nil {
		t.Fatalf("prepareIntegration: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://wild-port", nil)
	req.Header.Set("X-AT-Destination", "https://foo.example.com")
	dest, err := integ.resolveRequestDestination(req)
	if err != nil {
		t.Fatalf("resolveRequestDestination: %v", err)
	}
	if dest.Host != "foo.example.com:8443" {
		t.Fatalf("unexpected host: %s", dest.Host)
	}

	req = httptest.NewRequest(http.MethodGet, "http://wild-port", nil)
	req.Header.Set("X-AT-Destination", "https://foo.example.com:9443")
	if _, err := integ.resolveRequestDestination(req); err == nil {
		t.Fatal("expected error for mismatched port")
	}

	req = httptest.NewRequest(http.MethodGet, "http://wild-port", nil)
	req.Header.Set("X-AT-Destination", "https://foo.example.com:8443")
	if _, err := integ.resolveRequestDestination(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveRequestDestinationStatic(t *testing.T) {
	integ := &Integration{Name: "static", Destination: "https://api.example.com"}
	if err := prepareIntegration(integ); err != nil {
		t.Fatalf("prepareIntegration: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://static", nil)
	dest, err := integ.resolveRequestDestination(req)
	if err != nil {
		t.Fatalf("resolveRequestDestination: %v", err)
	}
	if dest.String() != "https://api.example.com" {
		t.Fatalf("unexpected destination: %s", dest)
	}
}

func TestContextWithResolvedDestination(t *testing.T) {
	dest, err := url.Parse("https://foo.example.com/base")
	if err != nil {
		t.Fatalf("failed to parse destination: %v", err)
	}

	ctx := contextWithResolvedDestination(context.Background(), dest)

	got, ok := resolvedDestinationFromContext(ctx)
	if !ok {
		t.Fatal("expected destination in context")
	}
	if got != dest {
		t.Fatalf("unexpected destination pointer: %p != %p", got, dest)
	}
	if resolvedDestinationApplied(ctx) {
		t.Fatal("destination should not be marked applied by default")
	}

	markResolvedDestinationApplied(ctx)
	if !resolvedDestinationApplied(ctx) {
		t.Fatal("expected destination to be marked applied")
	}

	got2, ok := resolvedDestinationFromContext(ctx)
	if !ok || got2 != dest {
		t.Fatal("resolved destination should remain available after marking applied")
	}
}

func TestResolvedDestinationMissing(t *testing.T) {
	ctx := context.Background()
	if dest, ok := resolvedDestinationFromContext(ctx); ok || dest != nil {
		t.Fatalf("expected no destination in empty context, got %v", dest)
	}
	if resolvedDestinationApplied(ctx) {
		t.Fatal("destination should not be marked applied when absent")
	}
}

func TestApplyResolvedDestination(t *testing.T) {
	dest, err := url.Parse("https://backend.example.com:8443/base?token=1")
	if err != nil {
		t.Fatalf("failed to parse destination: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://incoming/request?user=alice", nil)
	req = req.WithContext(contextWithResolvedDestination(req.Context(), dest))

	applyResolvedDestination(req, dest)

	if got := req.URL.Scheme; got != "https" {
		t.Fatalf("unexpected scheme %q", got)
	}
	if got := req.URL.Host; got != "backend.example.com:8443" {
		t.Fatalf("unexpected url host %q", got)
	}
	if got := req.Host; got != "backend.example.com:8443" {
		t.Fatalf("unexpected request host %q", got)
	}
	if got := req.URL.Path; got != "/base/request" {
		t.Fatalf("unexpected path %q", got)
	}
	if got := req.URL.RawQuery; got != "token=1&user=alice" {
		t.Fatalf("unexpected query %q", got)
	}
	if !resolvedDestinationApplied(req.Context()) {
		t.Fatal("expected destination to be marked applied")
	}

	got, ok := resolvedDestinationFromContext(req.Context())
	if !ok || got != dest {
		t.Fatal("expected destination to remain in context after application")
	}
}

func TestPrepareIntegrationWildcardDirector(t *testing.T) {
	integ := &Integration{Name: "wilddir", Destination: "https://*.example.com/base"}
	if err := prepareIntegration(integ); err != nil {
		t.Fatalf("prepareIntegration: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://wilddir/original", nil)
	integ.proxy.Director(req)
	if req.Host != integ.destinationURL.Host {
		t.Fatalf("expected host to be %q, got %q", integ.destinationURL.Host, req.Host)
	}

	dest, err := url.Parse("https://foo.example.com/newbase")
	if err != nil {
		t.Fatalf("parse dest: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "http://wilddir/target", nil)
	req = req.WithContext(contextWithResolvedDestination(req.Context(), dest))
	integ.proxy.Director(req)
	if req.Host != "foo.example.com" || req.URL.Path != "/newbase/target" {
		t.Fatalf("destination not applied: host=%s path=%s", req.Host, req.URL.Path)
	}

	appliedCtx := contextWithResolvedDestination(context.Background(), dest)
	markResolvedDestinationApplied(appliedCtx)
	req = httptest.NewRequest(http.MethodGet, "http://wilddir/skip", nil)
	req = req.WithContext(appliedCtx)
	integ.proxy.Director(req)
	if req.Host == "foo.example.com" {
		t.Fatalf("director should skip already-applied destination")
	}

	resp := &http.Response{StatusCode: http.StatusInternalServerError, Header: http.Header{}, Request: req}
	if err := integ.proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("modify response: %v", err)
	}
	if resp.Header.Get("X-AT-Upstream-Error") != "true" {
		t.Fatalf("expected upstream error header to be set")
	}
}

func TestPrepareIntegrationWildcardValidation(t *testing.T) {
	cases := []struct {
		name        string
		destination string
	}{
		{name: "user_info", destination: "https://user@*.example.com"},
		{name: "scheme_star", destination: "h*tp://*.example.com"},
		{name: "path_star", destination: "https://*.example.com/foo*"},
		{name: "port_star", destination: "https://*.example.com:*"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			integ := &Integration{Name: tc.name, Destination: tc.destination}
			if err := prepareIntegration(integ); err == nil {
				t.Fatalf("expected error for destination %q", tc.destination)
			}
		})
	}
}

func TestPrepareIntegrationWildcardFlags(t *testing.T) {
	integ := &Integration{Name: "flags", Destination: "https://*.Example.COM"}
	if err := prepareIntegration(integ); err != nil {
		t.Fatalf("prepareIntegration: %v", err)
	}
	if !integ.requiresDestinationHeader {
		t.Fatal("expected wildcard integration to require destination header")
	}
	if integ.wildcardHostPattern != "*.example.com" {
		t.Fatalf("unexpected wildcard host pattern: %q", integ.wildcardHostPattern)
	}
}

func TestPrepareIntegrationWildcardCatchAll(t *testing.T) {
	integ := &Integration{Name: "catchall", Destination: "https://*/"}
	if err := prepareIntegration(integ); err != nil {
		t.Fatalf("prepareIntegration: %v", err)
	}
	if !integ.requiresDestinationHeader {
		t.Fatal("expected wildcard integration to require destination header")
	}
	if integ.wildcardHostPattern != "*" {
		t.Fatalf("unexpected wildcard host pattern: %q", integ.wildcardHostPattern)
	}
}

func TestPrepareIntegrationWildcardPortStar(t *testing.T) {
	integ := &Integration{Name: "portstar", Destination: "https://*.example.com:*"}
	if err := prepareIntegration(integ); err == nil {
		t.Fatal("expected error for wildcard port")
	}
}

func TestPrepareIntegrationWildcardMissingBase(t *testing.T) {
	integ := &Integration{Name: "missingbase", Destination: "https://*./"}
	if err := prepareIntegration(integ); err == nil {
		t.Fatal("expected error for missing base domain")
	}
}

func TestMatchWildcardHost(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		host     string
		expected bool
	}{
		{name: "exact", pattern: "api.example.com", host: "api.example.com", expected: true},
		{name: "exact_case", pattern: "API.EXAMPLE.COM", host: "api.example.com", expected: true},
		{name: "wildcard_prefix", pattern: "*.example.com", host: "foo.example.com", expected: true},
		{name: "wildcard_multi", pattern: "*.example.com", host: "foo.bar.example.com", expected: true},
		{name: "wildcard_requires_subdomain", pattern: "*.example.com", host: "example.com", expected: false},
		{name: "wildcard_suffix", pattern: "api.*.example.com", host: "api.foo.example.com", expected: true},
		{name: "wildcard_suffix_miss", pattern: "api.*.example.com", host: "api.example.com", expected: false},
		{name: "prefix_mismatch", pattern: "api.*.example.com", host: "foo.example.com", expected: false},
		{name: "missing_middle_segment", pattern: "api.*.example.com", host: "api.example.org", expected: false},
		{name: "multi_segment_match", pattern: "a*b*c", host: "axbyc", expected: true},
		{name: "catch_all", pattern: "*", host: "example.com", expected: true},
		{name: "missing_middle", pattern: "a*b*c", host: "ac", expected: false},
		{name: "no_pattern", pattern: "", host: "", expected: true},
		{name: "no_pattern_host", pattern: "", host: "example.com", expected: false},
		{name: "missing_subdomain_same_length", pattern: "*.example.com", host: ".example.com", expected: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchWildcardHost(tc.pattern, tc.host); got != tc.expected {
				t.Fatalf("matchWildcardHost(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.expected)
			}
		})
	}
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

func TestDeleteIntegrationRemovesAllowlist(t *testing.T) {
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	name := "delal"
	i := &Integration{Name: name, Destination: "http://example.com"}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := SetAllowlist(name, []CallerConfig{{ID: "*"}}); err != nil {
		t.Fatalf("set allowlist: %v", err)
	}
	DeleteIntegration(name)
	if got := GetAllowlist(name); len(got) != 0 {
		t.Fatalf("allowlist not removed: %v", got)
	}
}

func TestIntegrationRateLimitWindow(t *testing.T) {
	i := &Integration{
		Name:            "window",
		Destination:     "http://example.com",
		InRateLimit:     1,
		OutRateLimit:    1,
		RateLimitWindow: "30ms",
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
	time.Sleep(40 * time.Millisecond)
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

func TestIntegrationTransportSettings(t *testing.T) {
	i := &Integration{
		Name:                  "tr",
		Destination:           "http://example.com",
		IdleConnTimeout:       "2s",
		TLSHandshakeTimeout:   "1s",
		ResponseHeaderTimeout: "3s",
		TLSInsecureSkipVerify: true,
		MaxIdleConns:          5,
		MaxIdleConnsPerHost:   3,
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})

	tr, ok := i.proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected http.Transport, got %T", i.proxy.Transport)
	}
	if tr.IdleConnTimeout != 2*time.Second || tr.TLSHandshakeTimeout != 1*time.Second || tr.ResponseHeaderTimeout != 3*time.Second {
		t.Fatalf("transport timeouts not applied")
	}
	if tr.MaxIdleConns != 5 || tr.MaxIdleConnsPerHost != 3 {
		t.Fatalf("idle connection limits not applied")
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("TLS settings not applied")
	}
}

func TestAddIntegrationInvalidTimeouts(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*Integration)
		msg  string
	}{
		{
			name: "idlebadformat",
			mod:  func(i *Integration) { i.IdleConnTimeout = "bogus" },
			msg:  "invalid idle_conn_timeout",
		},
		{
			name: "idlebadneg",
			mod:  func(i *Integration) { i.IdleConnTimeout = "-1s" },
			msg:  "invalid idle_conn_timeout",
		},
		{
			name: "handbadformat",
			mod:  func(i *Integration) { i.TLSHandshakeTimeout = "bogus" },
			msg:  "invalid tls_handshake_timeout",
		},
		{
			name: "handneg",
			mod:  func(i *Integration) { i.TLSHandshakeTimeout = "-1s" },
			msg:  "invalid tls_handshake_timeout",
		},
		{
			name: "respbadformat",
			mod:  func(i *Integration) { i.ResponseHeaderTimeout = "bogus" },
			msg:  "invalid response_header_timeout",
		},
		{
			name: "respneg",
			mod:  func(i *Integration) { i.ResponseHeaderTimeout = "-1s" },
			msg:  "invalid response_header_timeout",
		},
	}

	for _, tt := range cases {
		i := &Integration{
			Name:        tt.name,
			Destination: "http://example.com",
		}
		tt.mod(i)
		if err := AddIntegration(i); err == nil || !strings.Contains(err.Error(), tt.msg) {
			t.Errorf("%s: expected %s error, got %v", tt.name, tt.msg, err)
		}
	}
}

func TestIntegrationDisableKeepAlives(t *testing.T) {
	i := &Integration{
		Name:              "keep",
		Destination:       "http://example.com",
		InRateLimit:       1,
		OutRateLimit:      1,
		DisableKeepAlives: true,
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})

	tr, ok := i.proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected http.Transport, got %T", i.proxy.Transport)
	}
	if !tr.DisableKeepAlives {
		t.Fatalf("DisableKeepAlives not applied")
	}
}

func TestIntegrationPluginTransport(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	t.Setenv("CERT", string(certPEM))
	t.Setenv("KEY", string(keyPEM))

	p := mtls.MTLSAuthOut{}
	cfg, err := p.ParseParams(map[string]interface{}{"cert": "env:CERT", "key": "env:KEY"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	baseTr := p.Transport(cfg)
	if baseTr == nil {
		t.Fatal("missing base transport")
	}

	i := &Integration{
		Name:              "plug",
		Destination:       "http://example.com",
		InRateLimit:       1,
		OutRateLimit:      1,
		IdleConnTimeout:   "1s",
		DisableKeepAlives: true,
		OutgoingAuth: []AuthPluginConfig{{
			Type:   "mtls",
			Params: map[string]interface{}{"cert": "env:CERT", "key": "env:KEY"},
		}},
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	})

	tr, ok := i.proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected http.Transport, got %T", i.proxy.Transport)
	}
	if tr == baseTr {
		t.Fatalf("transport not cloned")
	}
	if tr.IdleConnTimeout != time.Second || !tr.DisableKeepAlives {
		t.Fatalf("integration settings not applied")
	}
	if baseTr.IdleConnTimeout != 0 {
		t.Fatalf("base transport mutated")
	}
	if tr.TLSClientConfig == nil || len(tr.TLSClientConfig.Certificates) == 0 {
		t.Fatalf("TLS certificates missing")
	}
	if !reflect.DeepEqual(tr.TLSClientConfig.Certificates, baseTr.TLSClientConfig.Certificates) {
		t.Fatalf("certificates not preserved")
	}
}

func TestAddIntegrationUnknownIncomingAuth(t *testing.T) {
	i := &Integration{
		Name:         "unknowninc",
		Destination:  "http://example.com",
		IncomingAuth: []AuthPluginConfig{{Type: "nope", Params: map[string]interface{}{}}},
	}
	if err := AddIntegration(i); err == nil || !strings.Contains(err.Error(), "unknown incoming auth type") {
		t.Fatalf("expected unknown incoming auth type error, got %v", err)
	}
}

func TestAddIntegrationUnknownOutgoingAuth(t *testing.T) {
	i := &Integration{
		Name:         "unknownout",
		Destination:  "http://example.com",
		OutgoingAuth: []AuthPluginConfig{{Type: "none", Params: map[string]interface{}{}}},
	}
	if err := AddIntegration(i); err == nil || !strings.Contains(err.Error(), "unknown outgoing auth type") {
		t.Fatalf("expected unknown outgoing auth type error, got %v", err)
	}
}

func TestAddIntegrationInvalidSecretRef(t *testing.T) {
	i := &Integration{
		Name:        "badsecret",
		Destination: "http://example.com",
		IncomingAuth: []AuthPluginConfig{{Type: "token", Params: map[string]interface{}{
			"secrets": []string{"bogus:VAL"},
			"header":  "X-Auth",
		}}},
	}
	if err := AddIntegration(i); err == nil || !strings.Contains(err.Error(), "unknown secret source") {
		t.Fatalf("expected secret validation error, got %v", err)
	}
}

func TestListIntegrationsIncludesAdded(t *testing.T) {
	i1 := &Integration{Name: "listone", Destination: "http://one.com"}
	if err := AddIntegration(i1); err != nil {
		t.Fatalf("add1: %v", err)
	}
	t.Cleanup(func() {
		i1.inLimiter.Stop()
		i1.outLimiter.Stop()
		DeleteIntegration("listone")
	})

	i2 := &Integration{Name: "listtwo", Destination: "http://two.com"}
	if err := AddIntegration(i2); err != nil {
		t.Fatalf("add2: %v", err)
	}
	t.Cleanup(func() {
		i2.inLimiter.Stop()
		i2.outLimiter.Stop()
		DeleteIntegration("listtwo")
	})

	names := map[string]bool{}
	for _, v := range ListIntegrations() {
		names[v.Name] = true
	}
	if !names["listone"] || !names["listtwo"] {
		t.Fatalf("ListIntegrations missing entries: %v", names)
	}
}

func TestGetIntegrationNotFound(t *testing.T) {
	if _, ok := GetIntegration("missing"); ok {
		t.Fatal("expected lookup failure")
	}
}

func TestAddIntegrationDefaultRateLimitWindow(t *testing.T) {
	i := &Integration{
		Name:         "defwin",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
		DeleteIntegration("defwin")
	})

	if i.inLimiter.window != time.Minute || i.outLimiter.window != time.Minute {
		t.Fatalf("expected default window 1m, got %v and %v", i.inLimiter.window, i.outLimiter.window)
	}
}

func TestAddIntegrationBadRateLimitWindowParse(t *testing.T) {
	i := &Integration{
		Name:            "badwin",
		Destination:     "http://example.com",
		RateLimitWindow: "notaduration",
	}
	if err := AddIntegration(i); err == nil || !strings.Contains(err.Error(), "invalid rate_limit_window") {
		t.Fatalf("expected rate limit window parse error, got %v", err)
	}
}

func TestAddIntegrationInvalidStrategy(t *testing.T) {
	i := &Integration{
		Name:              "badstrat",
		Destination:       "http://example.com",
		RateLimitStrategy: "bogus",
	}
	if err := AddIntegration(i); err == nil || !strings.Contains(err.Error(), "invalid rate_limit_strategy") {
		t.Fatalf("expected invalid strategy error, got %v", err)
	}
}

func TestAddIntegrationDefaultStrategy(t *testing.T) {
	i := &Integration{
		Name:         "defstrat",
		Destination:  "http://example.com",
		InRateLimit:  1,
		OutRateLimit: 1,
	}
	if err := AddIntegration(i); err != nil {
		t.Fatalf("add: %v", err)
	}
	t.Cleanup(func() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
		DeleteIntegration("defstrat")
	})
	if i.RateLimitStrategy != "fixed_window" {
		t.Fatalf("expected default strategy fixed_window, got %s", i.RateLimitStrategy)
	}
}

func TestPrepareIntegrationTransportSettings(t *testing.T) {
	i := &Integration{
		Name:                  "transport",
		Destination:           "https://example.com/base",
		IdleConnTimeout:       "2s",
		TLSHandshakeTimeout:   "3s",
		ResponseHeaderTimeout: "4s",
		TLSInsecureSkipVerify: true,
		DisableKeepAlives:     true,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   5,
		RateLimitWindow:       "2s",
		RateLimitStrategy:     "token_bucket",
	}
	if err := prepareIntegration(i); err != nil {
		t.Fatalf("prepareIntegration: %v", err)
	}

	tr, ok := i.proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", i.proxy.Transport)
	}
	if tr.IdleConnTimeout != 2*time.Second || tr.TLSHandshakeTimeout != 3*time.Second || tr.ResponseHeaderTimeout != 4*time.Second {
		t.Fatalf("transport durations not applied: %+v", tr)
	}
	if !tr.DisableKeepAlives || tr.MaxIdleConns != 10 || tr.MaxIdleConnsPerHost != 5 {
		t.Fatalf("transport numeric settings not applied: %+v", tr)
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("TLS settings not applied: %+v", tr.TLSClientConfig)
	}
}

func TestPrepareIntegrationOutgoingTransport(t *testing.T) {
	plugin := &outgoingTransportPlugin{transport: &http.Transport{DisableCompression: true}}
	authplugins.RegisterOutgoing(plugin)

	i := &Integration{
		Name:         "outtransport",
		Destination:  "http://example.com",
		OutgoingAuth: []AuthPluginConfig{{Type: plugin.Name(), Params: map[string]interface{}{}}},
	}
	if err := prepareIntegration(i); err != nil {
		t.Fatalf("prepareIntegration: %v", err)
	}
	tr, ok := i.proxy.Transport.(*http.Transport)
	if !ok || !tr.DisableCompression {
		t.Fatalf("expected proxy transport override to be cloned: %+v", i.proxy.Transport)
	}
}

func TestPrepareIntegrationTLSInsecureConfig(t *testing.T) {
	oldConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig
	http.DefaultTransport.(*http.Transport).TLSClientConfig = nil
	t.Cleanup(func() {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = oldConfig
	})

	integ := &Integration{Name: "tls-skip", Destination: "https://example.com", TLSInsecureSkipVerify: true}
	if err := prepareIntegration(integ); err != nil {
		t.Fatalf("prepareIntegration: %v", err)
	}
	tr, ok := integ.proxy.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected TLS client config with insecure skip verify enabled: %+v", integ.proxy.Transport)
	}
}

func TestPrepareIntegrationAuthValidationErrors(t *testing.T) {
	authplugins.RegisterIncoming(failingIncomingPlugin{})
	authplugins.RegisterOutgoing(failingOutgoingPlugin{})

	badIncoming := &Integration{
		Name:         "authfail-in",
		Destination:  "http://example.com",
		IncomingAuth: []AuthPluginConfig{{Type: "failing-incoming", Params: map[string]interface{}{}}},
	}
	if err := prepareIntegration(badIncoming); err == nil || !strings.Contains(err.Error(), "required param") {
		t.Fatalf("expected missing param error, got %v", err)
	}

	badOutgoing := &Integration{
		Name:         "authfail-out",
		Destination:  "http://example.com",
		OutgoingAuth: []AuthPluginConfig{{Type: "failing-outgoing", Params: map[string]interface{}{}}},
	}
	if err := prepareIntegration(badOutgoing); err == nil || !strings.Contains(err.Error(), "parse failure") {
		t.Fatalf("expected outgoing parse failure, got %v", err)
	}
}

func TestPrepareIntegrationOutgoingValidateRequired(t *testing.T) {
	authplugins.RegisterOutgoing(missingFieldOutgoingPlugin{})
	integ := &Integration{
		Name:         "missing-field-out",
		Destination:  "http://example.com",
		OutgoingAuth: []AuthPluginConfig{{Type: "missing-field-out", Params: map[string]interface{}{}}},
	}
	if err := prepareIntegration(integ); err == nil || !strings.Contains(err.Error(), "required param") {
		t.Fatalf("expected required param error, got %v", err)
	}
}

func TestPrepareIntegrationOutgoingSecretValidation(t *testing.T) {
	authplugins.RegisterOutgoing(secretFailOutgoingPlugin{})
	integ := &Integration{
		Name:         "secret-out",
		Destination:  "http://example.com",
		OutgoingAuth: []AuthPluginConfig{{Type: "secret-fail-out", Params: map[string]interface{}{}}},
	}
	if err := prepareIntegration(integ); err == nil || !strings.Contains(err.Error(), "unknown secret source") {
		t.Fatalf("expected secret validation error, got %v", err)
	}
}

func TestPrepareIntegrationWildcardPortHook(t *testing.T) {
	orig := parseURL
	parseURL = func(string) (*url.URL, error) {
		return &url.URL{Scheme: "https", Host: "*.example.com:*"}, nil
	}
	t.Cleanup(func() { parseURL = orig })

	integ := &Integration{Name: "port-hook", Destination: "https://*.example.com:*"}
	if err := prepareIntegration(integ); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("expected port error, got %v", err)
	}
}

func TestUpdateIntegrationRespectsWindow(t *testing.T) {
	integ := &Integration{
		Name:              "update-window",
		Destination:       "http://example.com",
		InRateLimit:       1,
		OutRateLimit:      1,
		RateLimitWindow:   "2s",
		RateLimitStrategy: "token_bucket",
	}
	if err := UpdateIntegration(integ); err != nil {
		t.Fatalf("update integration: %v", err)
	}
	got, ok := GetIntegration("update-window")
	if !ok {
		t.Fatalf("integration missing after update")
	}
	t.Cleanup(func() {
		got.inLimiter.Stop()
		got.outLimiter.Stop()
		DeleteIntegration("update-window")
	})
	if got.inLimiter.window != 2*time.Second || got.outLimiter.window != 2*time.Second {
		t.Fatalf("expected 2s window, got %v and %v", got.inLimiter.window, got.outLimiter.window)
	}
}

func TestUpdateIntegrationError(t *testing.T) {
	bad := &Integration{Name: "bad|name", Destination: "http://example.com"}
	if err := UpdateIntegration(bad); err == nil {
		t.Fatal("expected validation error")
	}
}
