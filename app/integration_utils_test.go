package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

type secretCfg struct {
	Secrets   []string
	Extra     []string `json:"SeCrEtS"`
	NotSlice  string   `json:"secrets"`
	NotString []int    `json:"sEcReTs"`
}

func TestCollectSecretRefs(t *testing.T) {
	cfg := &secretCfg{
		Secrets:   []string{"a", "b"},
		Extra:     []string{"c", "d"},
		NotSlice:  "x",
		NotString: []int{1, 2},
	}
	refs := collectSecretRefs(cfg)
	want := []string{"a", "b", "c", "d"}
	if !reflect.DeepEqual(refs, want) {
		t.Fatalf("expected %v, got %v", want, refs)
	}
}

func TestCollectSecretRefsNonStruct(t *testing.T) {
	if refs := collectSecretRefs(42); refs != nil {
		t.Fatalf("expected nil, got %v", refs)
	}
}

type secretTags struct {
	Secrets []string `json:",omitempty"`
	Tagged  []string `json:"secrets,omitempty"`
	Skip    []string `json:"-"`
}

func TestCollectSecretRefsTagVariants(t *testing.T) {
	cfg := secretTags{
		Secrets: []string{"a"},
		Tagged:  []string{"b"},
		Skip:    []string{"c"},
	}
	refs := collectSecretRefs(cfg)
	if want := []string{"a", "b"}; !reflect.DeepEqual(refs, want) {
		t.Fatalf("expected %v, got %v", want, refs)
	}
}

func TestSingleJoiningSlash(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want string
	}{
		{name: "both_slash", a: "base/", b: "/path", want: "base/path"},
		{name: "no_slash_nonempty", a: "base", b: "path", want: "base/path"},
		{name: "either_empty", a: "", b: "path", want: "path"},
		{name: "one_slash", a: "base/", b: "path", want: "base/path"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := singleJoiningSlash(tc.a, tc.b); got != tc.want {
				t.Fatalf("singleJoiningSlash(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestJoinProxyPathRawPaths(t *testing.T) {
	target, err := url.Parse("https://example.com/base/segment")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	target.RawPath = "/base%2Fsegment"

	req := httptest.NewRequest(http.MethodGet, "http://incoming/request%2Fchild", nil)
	req.URL.Path = "/request/child"
	req.URL.RawPath = "/request%2Fchild"

	path, raw := joinProxyPath(target, req)
	if path != "/base/segment/request/child" {
		t.Fatalf("unexpected path %q", path)
	}
	if raw != "/base%2Fsegment/request%2Fchild" {
		t.Fatalf("unexpected raw path %q", raw)
	}
}

func TestJoinProxyPathRequestRawOnly(t *testing.T) {
	target, err := url.Parse("https://example.com/base")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://incoming/child", nil)
	req.URL.Path = "child"
	req.URL.RawPath = "child%2Fenc"

	path, raw := joinProxyPath(target, req)
	if path != "/base/child" {
		t.Fatalf("unexpected path %q", path)
	}
	if raw != "/base/child" {
		t.Fatalf("unexpected raw path %q", raw)
	}
}

func TestJoinProxyPathNoRaw(t *testing.T) {
	target, err := url.Parse("https://example.com/base/")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://incoming/path", nil)

	path, raw := joinProxyPath(target, req)
	if raw != "" {
		t.Fatalf("expected empty raw path, got %q", raw)
	}
	if path != "/base/path" {
		t.Fatalf("unexpected path %q", path)
	}
}

func TestJoinProxyPathBothSlashRaw(t *testing.T) {
	target, err := url.Parse("https://example.com/base/")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	target.RawPath = "/base/"

	req := httptest.NewRequest(http.MethodGet, "http://incoming/child", nil)
	req.URL.Path = "/child"
	req.URL.RawPath = "/child"

	path, raw := joinProxyPath(target, req)
	if path != "/base/child" || raw != "/base/child" {
		t.Fatalf("unexpected join result path=%q raw=%q", path, raw)
	}
}

func TestJoinProxyPathSwitchCases(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		requestPath string
		expected    string
	}{
		{name: "both_have_slash", target: "https://ex.com/base/", requestPath: "/child", expected: "/base/child"},
		{name: "neither_slash", target: "https://ex.com/base", requestPath: "child", expected: "/base/child"},
		{name: "default", target: "https://ex.com/base", requestPath: "/child", expected: "/base/child"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tgt, err := url.Parse(tc.target)
			if err != nil {
				t.Fatalf("parse target: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://incoming/"+strings.TrimPrefix(tc.requestPath, "/"), nil)
			req.URL.Path = tc.requestPath
			path, _ := joinProxyPath(tgt, req)
			if path != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, path)
			}
		})
	}
}
