package findreplace

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/winhowes/AuthTranslator/app/secrets"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestFindReplaceAddAuth(t *testing.T) {
	r := &http.Request{
		URL:    &url.URL{Scheme: "http", Host: "host", Path: "/PLACE", RawQuery: "q=PLACE"},
		Header: http.Header{"H-PLACE": []string{"val PLACE"}},
		Body:   io.NopCloser(strings.NewReader("body PLACE")),
		Host:   "host",
	}
	p := FindReplace{}
	t.Setenv("FIND", "PLACE")
	t.Setenv("REP", "SECRET")
	cfg, err := p.ParseParams(map[string]interface{}{"find_secret": "env:FIND", "replace_secret": "env:REP"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if r.URL.Path != "/SECRET" || r.URL.RawQuery != "q=SECRET" {
		t.Fatalf("unexpected url %s?%s", r.URL.Path, r.URL.RawQuery)
	}
	if v := r.Header.Get("H-SECRET"); v != "val SECRET" {
		t.Fatalf("unexpected header value %s", v)
	}
	if _, ok := r.Header["H-PLACE"]; ok {
		t.Fatal("old header still present")
	}
	body, _ := io.ReadAll(r.Body)
	if string(body) != "body SECRET" {
		t.Fatalf("unexpected body %q", string(body))
	}
}

func TestFindReplaceAddAuthLiteralFind(t *testing.T) {
	r := &http.Request{
		URL:    &url.URL{Scheme: "http", Host: "host", Path: "/__PLACE__", RawQuery: "q=__PLACE__"},
		Header: http.Header{"__PLACE__-Header": []string{"body __PLACE__"}},
		Body:   io.NopCloser(strings.NewReader("__PLACE__ payload")),
		Host:   "host",
	}
	p := FindReplace{}
	t.Setenv("REP", "SECRET")
	cfg, err := p.ParseParams(map[string]interface{}{"find_secret": "dangerousLiteral:__PLACE__", "replace_secret": "env:REP"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}

	if r.URL.Path != "/SECRET" || r.URL.RawQuery != "q=SECRET" {
		t.Fatalf("unexpected url %s?%s", r.URL.Path, r.URL.RawQuery)
	}
	if v := r.Header.Get("SECRET-Header"); v != "body SECRET" {
		t.Fatalf("unexpected header value %s", v)
	}
	if _, ok := r.Header["__PLACE__-Header"]; ok {
		t.Fatal("old header still present")
	}
	body, _ := io.ReadAll(r.Body)
	if string(body) != "SECRET payload" {
		t.Fatalf("unexpected body %q", string(body))
	}
}

func TestFindReplaceAddAuthNoMatch(t *testing.T) {
	r := &http.Request{URL: &url.URL{Path: "/foo"}, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("bar"))}
	p := FindReplace{}
	t.Setenv("F", "x")
	t.Setenv("R", "y")
	cfg, err := p.ParseParams(map[string]interface{}{"find_secret": "env:F", "replace_secret": "env:R"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if r.URL.Path != "/foo" || r.URL.RawQuery != "" {
		t.Fatalf("url changed: %s?%s", r.URL.Path, r.URL.RawQuery)
	}
	if len(r.Header) != 0 {
		t.Fatalf("headers changed: %v", r.Header)
	}
	b, _ := io.ReadAll(r.Body)
	if string(b) != "bar" {
		t.Fatalf("body changed: %q", string(b))
	}
}

type failPlugin struct{}

func (failPlugin) Prefix() string                               { return "fail" }
func (failPlugin) Load(context.Context, string) (string, error) { return "", io.EOF }

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (errReadCloser) Close() error             { return nil }

func TestFindReplaceEdgeCases(t *testing.T) {
	secrets.Register(failPlugin{})
	p := FindReplace{}
	t.Setenv("FIND", "a")
	t.Setenv("REP", "b")
	cfg := &outParams{FindSecret: "env:FIND", ReplaceSecret: "env:REP"}

	// invalid params type
	r := &http.Request{URL: &url.URL{Path: "/"}, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}
	if err := p.AddAuth(context.Background(), r, struct{}{}); err == nil {
		t.Fatal("expected error")
	}
	// missing secrets
	if err := p.AddAuth(context.Background(), r, &outParams{}); err == nil {
		t.Fatal("expected error")
	}
	// secret load error
	badCfg := &outParams{FindSecret: "fail:x", ReplaceSecret: "env:REP"}
	if err := p.AddAuth(context.Background(), r, badCfg); err == nil {
		t.Fatal("expected error")
	}
	badCfg = &outParams{FindSecret: "env:FIND", ReplaceSecret: "fail:x"}
	if err := p.AddAuth(context.Background(), r, badCfg); err == nil {
		t.Fatal("expected error")
	}
	// body read error
	r.Body = errReadCloser{}
	if err := p.AddAuth(context.Background(), r, cfg); err == nil {
		t.Fatal("expected error")
	}
}

func TestFindReplaceParseParams(t *testing.T) {
	p := FindReplace{}
	t.Setenv("F", "a")
	t.Setenv("R", "b")
	cfg, err := p.ParseParams(map[string]interface{}{"find_secret": "env:F", "replace_secret": "env:R"})
	if err != nil {
		t.Fatal(err)
	}
	if c := cfg.(*outParams); c.FindSecret != "env:F" || c.ReplaceSecret != "env:R" {
		t.Fatalf("unexpected cfg %#v", c)
	}
	if _, err := p.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := p.ParseParams(map[string]interface{}{"find_secret": 1, "replace_secret": "env:R"}); err == nil {
		t.Fatal("expected type error")
	}
	if _, err := p.ParseParams(map[string]interface{}{"find_secret": "env:F", "replace_secret": "env:R", "extra": true}); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestFindReplaceMethods(t *testing.T) {
	p := FindReplace{}
	if p.Name() != "find_replace" {
		t.Fatalf("unexpected name %s", p.Name())
	}
	rp := p.RequiredParams()
	if len(rp) != 2 || rp[0] != "find_secret" || rp[1] != "replace_secret" {
		t.Fatalf("unexpected required params %v", rp)
	}
	if op := p.OptionalParams(); op != nil {
		t.Fatalf("unexpected optional params %v", op)
	}
}
