package passthrough

import (
	"context"
	"net/http"
	"testing"
)

func TestPassThruIncomingAlways(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	p := PassThruAuth{}
	cfg, err := p.ParseParams(map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Authenticate(context.Background(), r, cfg) {
		t.Fatal("expected authentication to always succeed")
	}
}

func TestPassThruOutgoingNoop(t *testing.T) {
	r := &http.Request{Header: http.Header{"X-Test": []string{"value"}}}
	p := PassThruAuthOut{}
	cfg, err := p.ParseParams(map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddAuth(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("X-Test"); got != "value" {
		t.Fatalf("expected header to remain unchanged, got %s", got)
	}
}

func TestPassThruPluginParams(t *testing.T) {
	in := PassThruAuth{}
	out := PassThruAuthOut{}
	if in.RequiredParams() != nil && len(in.RequiredParams()) != 0 {
		t.Fatalf("unexpected required params: %v", in.RequiredParams())
	}
	if out.RequiredParams() != nil && len(out.RequiredParams()) != 0 {
		t.Fatalf("unexpected required params: %v", out.RequiredParams())
	}
	if in.OptionalParams() != nil && len(in.OptionalParams()) != 0 {
		t.Fatalf("unexpected optional params: %v", in.OptionalParams())
	}
	if out.OptionalParams() != nil && len(out.OptionalParams()) != 0 {
		t.Fatalf("unexpected optional params: %v", out.OptionalParams())
	}
}

func TestPassThruParseParamsError(t *testing.T) {
	in := PassThruAuth{}
	if _, err := in.ParseParams(map[string]interface{}{"foo": true}); err == nil {
		t.Fatal("expected error for unknown field in incoming parse")
	}
	out := PassThruAuthOut{}
	if _, err := out.ParseParams(map[string]interface{}{"bar": 1}); err == nil {
		t.Fatal("expected error for unknown field in outgoing parse")
	}
}
