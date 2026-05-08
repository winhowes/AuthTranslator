package envoy_xfcc

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
)

func TestEnvoyXFCCSingleElementAllowed(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"allowed_uris": []string{"spiffe://example/ns/default/sa/caller"}})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{"X-Forwarded-Client-Cert": []string{"By=spiffe://proxy;URI=spiffe://example/ns/default/sa/caller"}}}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication success")
	}
}

func TestEnvoyXFCCMissingHeaderFails(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"allowed_uris": []string{"spiffe://allowed"}})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{}}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected missing header to fail")
	}
}

func TestEnvoyXFCCDisallowedURIFails(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"allowed_uris": []string{"spiffe://allowed"}})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{"X-Forwarded-Client-Cert": []string{"URI=spiffe://denied"}}}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected disallowed uri to fail")
	}
}

func TestEnvoyXFCCAuthenticateFailureLogsHeaders(t *testing.T) {
	var buf bytes.Buffer
	oldLogger := authplugins.SetLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { authplugins.SetLogger(oldLogger) })

	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"allowed_uris": []string{"spiffe://allowed"}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://internal.example/resource", nil)
	r.Header.Add("X-Forwarded-Client-Cert", "URI=spiffe://denied")
	r.Header.Add("X-Forwarded-Client-Cert", "URI=spiffe://also-denied")
	r.Header.Set("X-Debug-Header", "debug-value")

	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to fail")
	}

	got := buf.String()
	for _, want := range []string{
		`"msg":"envoy_xfcc authentication failed"`,
		`"reason":"authentication_failed"`,
		`"configured_header":"X-Forwarded-Client-Cert"`,
		"X-Forwarded-Client-Cert",
		"spiffe://denied",
		"spiffe://also-denied",
		"X-Debug-Header",
		"debug-value",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected log to contain %q; got %s", want, got)
		}
	}
}

func TestEnvoyXFCCAuthenticateSuccessDoesNotLogHeaders(t *testing.T) {
	var buf bytes.Buffer
	oldLogger := authplugins.SetLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { authplugins.SetLogger(oldLogger) })

	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"allowed_uris": []string{"spiffe://allowed"}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://internal.example/resource", nil)
	r.Header.Set("X-Forwarded-Client-Cert", "URI=spiffe://allowed")

	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to succeed")
	}
	if got := buf.String(); got != "" {
		t.Fatalf("expected no auth failure log, got %s", got)
	}
}

func TestEnvoyXFCCAuthenticateInvalidParamsFails(t *testing.T) {
	p := EnvoyXFCCAuth{}
	if p.Authenticate(context.Background(), nil, struct{}{}) {
		t.Fatal("expected invalid params to fail")
	}
}

func TestEnvoyXFCCIdentifyExtractionFailure(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"allowed_uris": []string{"spiffe://allowed"}})
	if err != nil {
		t.Fatal(err)
	}
	id, ok := p.Identify(&http.Request{Header: http.Header{}}, cfg)
	if ok || id != "" {
		t.Fatalf("expected identify failure, got id=%q ok=%v", id, ok)
	}
}

func TestEnvoyXFCCMultipleNonIgnoredURIsFails(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"allowed_uri_prefixes": []string{"spiffe://"}})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{"X-Forwarded-Client-Cert": []string{"URI=spiffe://caller-a,URI=spiffe://caller-b"}}}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected multiple caller identities to fail")
	}
}

func TestEnvoyXFCCMultipleURIFieldsInElementFails(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"allowed_uri_prefixes": []string{"spiffe://"}})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{"X-Forwarded-Client-Cert": []string{"URI=spiffe://caller-a;URI=spiffe://caller-b"}}}
	if p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected multiple URI fields in one element to fail")
	}
}

func TestEnvoyXFCCIgnoredProxyAndAllowedCallerSucceeds(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"allowed_uris": []string{"spiffe://cluster.local/ns/team/sa/caller"},
		"ignored_uris": []string{"spiffe://cluster.local/ns/gw/sa/envoy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{"X-Forwarded-Client-Cert": []string{"URI=spiffe://cluster.local/ns/gw/sa/envoy,URI=spiffe://cluster.local/ns/team/sa/caller"}}}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected caller URI to be accepted after ignoring gateway URI")
	}
}

func TestEnvoyXFCCQuotedSubjectWithSeparatorsParses(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"allowed_uris": []string{"spiffe://example/ns/default/sa/caller"}})
	if err != nil {
		t.Fatal(err)
	}
	value := "By=spiffe://proxy;Subject=\"CN=gw\\\"team\\\";OU=edge,region\";URI=spiffe://example/ns/default/sa/caller"
	r := &http.Request{Header: http.Header{"X-Forwarded-Client-Cert": []string{value}}}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected quoted subject separators to not break parser")
	}
}

func TestEnvoyXFCCIdentifyReturnsCallerURI(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"allowed_uri_prefixes": []string{"spiffe://example/ns/default/"}})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{"X-Forwarded-Client-Cert": []string{"URI=spiffe://example/ns/default/sa/caller"}}}
	id, ok := p.Identify(r, cfg)
	if !ok {
		t.Fatal("expected identify success")
	}
	if id != "spiffe://example/ns/default/sa/caller" {
		t.Fatalf("unexpected id %q", id)
	}
}

func TestEnvoyXFCCMultipleHeaderValuesCombined(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"allowed_uris": []string{"spiffe://cluster.local/ns/team/sa/caller"},
		"ignored_uris": []string{"spiffe://cluster.local/ns/gateway/sa/envoy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{}}
	r.Header.Add("X-Forwarded-Client-Cert", "URI=spiffe://cluster.local/ns/gateway/sa/envoy")
	r.Header.Add("X-Forwarded-Client-Cert", "URI=spiffe://cluster.local/ns/team/sa/caller")
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected auth success when caller URI is in a later header value")
	}
	id, ok := p.Identify(r, cfg)
	if !ok || id != "spiffe://cluster.local/ns/team/sa/caller" {
		t.Fatalf("unexpected identify result id=%q ok=%v", id, ok)
	}
}

func TestEnvoyXFCCJSONHeaderSupported(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"allowed_uris": []string{"spiffe://cluster.local/ns/team/sa/caller"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{}}
	r.Header.Set("X-Forwarded-Client-Cert", `{"URI":"spiffe://cluster.local/ns/team/sa/caller","Subject":"CN=client"}`)
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected JSON XFCC header to authenticate")
	}
}

func TestEnvoyXFCCJSONArrayWithIgnoredIdentity(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"allowed_uris": []string{"spiffe://cluster.local/ns/team/sa/caller"},
		"ignored_uris": []string{"spiffe://cluster.local/ns/gateway/sa/envoy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{}}
	r.Header.Set("X-Forwarded-Client-Cert", `[{"URI":"spiffe://cluster.local/ns/gateway/sa/envoy"},{"URI":"spiffe://cluster.local/ns/team/sa/caller"}]`)
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected JSON XFCC array with ignored gateway to authenticate")
	}
}

func TestEnvoyXFCCJSONMalformedOrMixedFails(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"allowed_uri_prefixes": []string{"spiffe://cluster.local/ns/team/"},
	})
	if err != nil {
		t.Fatal(err)
	}

	malformed := &http.Request{Header: http.Header{}}
	malformed.Header.Set("X-Forwarded-Client-Cert", `{"URI":`)
	if p.Authenticate(context.Background(), malformed, cfg) {
		t.Fatal("expected malformed JSON header to fail")
	}
	duplicateURIKeys := &http.Request{Header: http.Header{}}
	duplicateURIKeys.Header.Set("X-Forwarded-Client-Cert", `{"URI":"spiffe://cluster.local/ns/team/sa/caller","uri":"spiffe://cluster.local/ns/other/sa/caller"}`)
	if p.Authenticate(context.Background(), duplicateURIKeys, cfg) {
		t.Fatal("expected duplicate case-insensitive URI keys to fail")
	}
	duplicateExactURIKeys := &http.Request{Header: http.Header{}}
	duplicateExactURIKeys.Header.Set("X-Forwarded-Client-Cert", `{"URI":"spiffe://cluster.local/ns/other/sa/caller","URI":"spiffe://cluster.local/ns/team/sa/caller"}`)
	if p.Authenticate(context.Background(), duplicateExactURIKeys, cfg) {
		t.Fatal("expected duplicate exact URI keys to fail")
	}
	jsonWithTrailingGarbage := &http.Request{Header: http.Header{}}
	jsonWithTrailingGarbage.Header.Set("X-Forwarded-Client-Cert", `{"URI":"spiffe://cluster.local/ns/team/sa/caller"},URI=spiffe://cluster.local/ns/other/sa/caller`)
	if p.Authenticate(context.Background(), jsonWithTrailingGarbage, cfg) {
		t.Fatal("expected JSON XFCC header with trailing garbage to fail")
	}

	mixed := &http.Request{Header: http.Header{}}
	mixed.Header.Add("X-Forwarded-Client-Cert", `{"URI":"spiffe://cluster.local/ns/team/sa/caller"}`)
	mixed.Header.Add("X-Forwarded-Client-Cert", `URI=spiffe://cluster.local/ns/team/sa/caller`)
	if p.Authenticate(context.Background(), mixed, cfg) {
		t.Fatal("expected mixed JSON/text XFCC header values to fail")
	}
}

func TestEnvoyXFCCJSONCoverageEdges(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{
		"allowed_uri_prefixes": []string{"spiffe://ok/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := extractCallerIdentityFromValues(nil, cfg.(*inParams)); ok {
		t.Fatal("expected empty header values to fail")
	}
	if _, ok := extractCallerIdentityFromValues([]string{"   "}, cfg.(*inParams)); ok {
		t.Fatal("expected blank header value to fail")
	}
	if _, ok := extractCallerIdentity("", cfg.(*inParams)); ok {
		t.Fatal("expected blank text XFCC to fail")
	}
	if detectHeaderFormat("") != headerFormatUnknown {
		t.Fatal("expected unknown format for empty value")
	}
	if detectHeaderFormat("{\"URI\":\"spiffe://ok/a\"}") != headerFormatJSON {
		t.Fatal("expected JSON format detection")
	}
	if detectHeaderFormat("URI=spiffe://ok/a") != headerFormatText {
		t.Fatal("expected text format detection")
	}

	if uris, ok := extractJSONURIs(`{"By":"proxy"}`); !ok || len(uris) != 0 {
		t.Fatalf("expected JSON object without URI to succeed with empty URIs: uris=%v ok=%v", uris, ok)
	}
	if uris, ok := extractJSONURIs(`[{"URI":"spiffe://ok/a"}]`); !ok || len(uris) != 1 || uris[0] != "spiffe://ok/a" {
		t.Fatalf("unexpected JSON array parse uris=%v ok=%v", uris, ok)
	}
	if _, ok := extractJSONURIs(`["bad"]`); ok {
		t.Fatal("expected invalid JSON array element to fail")
	}
	if _, ok := extractJSONURIs(`{"URI":["a","b"]}`); ok {
		t.Fatal("expected URI array with multiple entries to fail")
	}
	if _, ok := extractJSONURIs(`{"URI":[""]}`); ok {
		t.Fatal("expected empty URI array entry to fail")
	}
	if _, ok := extractJSONURIs(`[`); ok {
		t.Fatal("expected malformed JSON array to fail")
	}
	if _, ok := extractJSONURIs(""); ok {
		t.Fatal("expected empty JSON string to fail")
	}
	if _, ok := extractJSONURIs(`[{"URI":1}]`); ok {
		t.Fatal("expected JSON array element with invalid URI to fail")
	}
	if _, ok := extractJSONURIs(`{"URI":1}`); ok {
		t.Fatal("expected non-string URI to fail")
	}

	if uri, ok := extractURIFromJSONObject(json.RawMessage(`{"By":"proxy"}`)); !ok || uri != "" {
		t.Fatalf("expected no URI in object: uri=%q ok=%v", uri, ok)
	}
	if uri, ok := extractURIFromJSONObject(json.RawMessage(`{"URI":["spiffe://ok/a"]}`)); !ok || uri != "spiffe://ok/a" {
		t.Fatalf("unexpected URI array decode: uri=%q ok=%v", uri, ok)
	}
	if uri, ok := extractURIFromJSONObject(json.RawMessage(`{"URI":" "}`)); ok || uri != "" {
		t.Fatalf("expected blank URI string to fail: uri=%q ok=%v", uri, ok)
	}
	if uri, ok := extractURIFromJSONObject(json.RawMessage(`[]`)); ok || uri != "" {
		t.Fatalf("expected non-object JSON to fail: uri=%q ok=%v", uri, ok)
	}
	if uri, ok := extractURIFromJSONObject(json.RawMessage(``)); ok || uri != "" {
		t.Fatalf("expected empty JSON object bytes to fail: uri=%q ok=%v", uri, ok)
	}
	if uri, ok := extractURIFromJSONObject(json.RawMessage(`{"URI":"spiffe://ok/a"`)); ok || uri != "" {
		t.Fatalf("expected unterminated JSON object to fail: uri=%q ok=%v", uri, ok)
	}
	if uri, ok := extractURIFromJSONObject(json.RawMessage(`{"URI":}`)); ok || uri != "" {
		t.Fatalf("expected invalid JSON URI value to fail: uri=%q ok=%v", uri, ok)
	}
	if uri, ok := extractURIFromJSONObject(json.RawMessage(`{"URI":"spiffe://ok/a",`)); ok || uri != "" {
		t.Fatalf("expected malformed trailing-comma object to fail: uri=%q ok=%v", uri, ok)
	}
	if uri, ok := extractURIFromJSONObject(json.RawMessage(`{"URI":"spiffe://ok/a"} trailing`)); ok || uri != "" {
		t.Fatalf("expected trailing tokens after JSON object to fail: uri=%q ok=%v", uri, ok)
	}
}

func TestEnvoyXFCCStripHeaderWhenEnabled(t *testing.T) {
	p := EnvoyXFCCAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{"allowed_uris": []string{"spiffe://allowed"}})
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: http.Header{"X-Forwarded-Client-Cert": []string{"URI=spiffe://allowed"}}}
	p.StripAuth(r, cfg)
	if got := r.Header.Get("X-Forwarded-Client-Cert"); got != "" {
		t.Fatalf("expected stripped header, got %q", got)
	}
}

func TestEnvoyXFCCCoverageEdges(t *testing.T) {
	p := EnvoyXFCCAuth{}
	if p.Name() != "envoy_xfcc" {
		t.Fatal("unexpected name")
	}
	if len(p.RequiredParams()) != 0 {
		t.Fatal("expected no required params")
	}
	if len(p.OptionalParams()) != 4 {
		t.Fatal("unexpected optional params")
	}

	if _, err := p.ParseParams(map[string]interface{}{"unknown": true}); err == nil {
		t.Fatal("expected unknown param error")
	}
	if _, err := p.ParseParams(map[string]interface{}{"allowed_uris": "bad"}); err == nil {
		t.Fatal("expected type mismatch")
	}

	cfgAny, err := p.ParseParams(map[string]interface{}{"allowed_uri_prefixes": []string{"spiffe://ok/"}, "header": "X-Custom-XFCC"})
	if err != nil {
		t.Fatal(err)
	}
	cfgAnyTyped := cfgAny.(*inParams)
	if cfgAnyTyped.Header != "X-Custom-XFCC" || len(cfgAnyTyped.AllowedURIPrefix) != 1 || cfgAnyTyped.AllowedURIPrefix[0] != "spiffe://ok/" {
		t.Fatalf("unexpected parsed config: %+v", cfgAnyTyped)
	}
	r := &http.Request{Header: http.Header{}}
	r.Header.Set("X-Custom-XFCC", "URI=spiffe://ok/caller")
	if !isAllowedIdentity("spiffe://ok/caller", cfgAnyTyped) {
		t.Fatal("expected allow-list prefix match")
	}
	if id, ok := extractCallerIdentity(r.Header.Get("X-Custom-XFCC"), cfgAnyTyped); !ok || id != "spiffe://ok/caller" {
		t.Fatalf("unexpected extract result id=%q ok=%v", id, ok)
	}
	if !p.Authenticate(context.Background(), r, cfgAny) {
		t.Fatal("expected custom header auth success")
	}
	if id, ok := p.Identify(r, nil); ok || id != "" {
		t.Fatal("expected identify false with invalid params")
	}
	p.StripAuth(r, cfgAny)
	if got := r.Header.Get("X-Custom-XFCC"); got != "" {
		t.Fatal("expected header stripped")
	}
	p.StripAuth(r, nil)

	malformed := &http.Request{Header: http.Header{}}
	malformed.Header.Set("X-Custom-XFCC", "URI=\"unterminated")
	if p.Authenticate(context.Background(), malformed, cfgAny) {
		t.Fatal("expected malformed quote to fail")
	}
	badField := &http.Request{Header: http.Header{}}
	badField.Header.Set("X-Custom-XFCC", "URI=spiffe://ok/caller;NoEquals")
	if p.Authenticate(context.Background(), badField, cfgAny) {
		t.Fatal("expected malformed field to fail")
	}
	noURI := &http.Request{Header: http.Header{}}
	noURI.Header.Set("X-Custom-XFCC", "By=spiffe://proxy")
	if p.Authenticate(context.Background(), noURI, cfgAny) {
		t.Fatal("expected no URI to fail")
	}
	emptyElem := &http.Request{Header: http.Header{}}
	emptyElem.Header.Set("X-Custom-XFCC", "URI=spiffe://ok/caller,")
	if p.Authenticate(context.Background(), emptyElem, cfgAny) {
		t.Fatal("expected trailing separator to fail")
	}
	quotedURI := &http.Request{Header: http.Header{}}
	quotedURI.Header.Set("X-Custom-XFCC", "URI=\"spiffe://ok/caller\"")
	if !p.Authenticate(context.Background(), quotedURI, cfgAny) {
		t.Fatal("expected quoted URI to succeed")
	}
	escapedURI := &http.Request{Header: http.Header{}}
	escapedURI.Header.Set("X-Custom-XFCC", "URI=\"spiffe://ok\\/caller\"")
	if !p.Authenticate(context.Background(), escapedURI, cfgAny) {
		t.Fatal("expected escaped quoted URI to succeed")
	}
	badQuotedURI := &http.Request{Header: http.Header{}}
	badQuotedURI.Header.Set("X-Custom-XFCC", "URI=\"spiffe://ok/caller\\\"")
	if p.Authenticate(context.Background(), badQuotedURI, cfgAny) {
		t.Fatal("expected dangling escape in URI value to fail")
	}
	emptyValue := &http.Request{Header: http.Header{}}
	emptyValue.Header.Set("X-Custom-XFCC", "URI=")
	if p.Authenticate(context.Background(), emptyValue, cfgAny) {
		t.Fatal("expected empty URI value to fail")
	}
	emptyKey := &http.Request{Header: http.Header{}}
	emptyKey.Header.Set("X-Custom-XFCC", "=spiffe://ok/caller")
	if p.Authenticate(context.Background(), emptyKey, cfgAny) {
		t.Fatal("expected empty key to fail")
	}
	emptyField := &http.Request{Header: http.Header{}}
	emptyField.Header.Set("X-Custom-XFCC", "URI=spiffe://ok/caller;;By=spiffe://proxy")
	if p.Authenticate(context.Background(), emptyField, cfgAny) {
		t.Fatal("expected empty field segment to fail")
	}
	if v, ok := decodeFieldValue("\""); ok || v != "" {
		t.Fatal("expected single-quote value to fail decoding")
	}
	if v, ok := decodeFieldValue("\"abc\\\""); ok || v != "" {
		t.Fatal("expected dangling escape inside quoted value to fail decoding")
	}
	values := []string{}
	if joined := joinHeaderValues(values); joined != "" {
		t.Fatalf("expected empty joined header, got %q", joined)
	}
	values = append(values, "URI=spiffe://ok/one", "URI=spiffe://ok/two")
	if joined := joinHeaderValues(values); joined != "URI=spiffe://ok/one,URI=spiffe://ok/two" {
		t.Fatalf("unexpected joined header %q", joined)
	}

	cfgIgnoredOnly, err := p.ParseParams(map[string]interface{}{
		"allowed_uri_prefixes": []string{"spiffe://ok/"},
		"ignored_uris":         []string{"spiffe://ok/caller"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ignoredOnly := &http.Request{Header: http.Header{"X-Forwarded-Client-Cert": []string{"URI=spiffe://ok/caller"}}}
	if p.Authenticate(context.Background(), ignoredOnly, cfgIgnoredOnly) {
		t.Fatal("expected ignored-only identities to fail")
	}

	cfgNoAllow, err := p.ParseParams(map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Authenticate(context.Background(), &http.Request{Header: http.Header{"X-Forwarded-Client-Cert": []string{"URI=spiffe://ok/caller"}}}, cfgNoAllow) {
		t.Fatal("expected no allow-lists to fail closed")
	}
}
