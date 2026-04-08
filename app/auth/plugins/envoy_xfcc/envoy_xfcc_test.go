package envoy_xfcc

import (
	"context"
	"net/http"
	"testing"
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
	h := http.Header{}
	if joined := joinHeaderValues(h, "X-Forwarded-Client-Cert"); joined != "" {
		t.Fatalf("expected empty joined header, got %q", joined)
	}
	h.Add("X-Forwarded-Client-Cert", "URI=spiffe://ok/one")
	h.Add("X-Forwarded-Client-Cert", "URI=spiffe://ok/two")
	if joined := joinHeaderValues(h, "X-Forwarded-Client-Cert"); joined != "URI=spiffe://ok/one,URI=spiffe://ok/two" {
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
