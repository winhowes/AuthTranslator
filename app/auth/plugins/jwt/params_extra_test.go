package jwt

import "testing"

func TestJWTParamFuncs(t *testing.T) {
	in := &JWTAuth{}
	out := &JWTAuthOut{}
	if in.Name() != "jwt" || out.Name() != "jwt" {
		t.Fatalf("name mismatch")
	}
	if len(in.RequiredParams()) != 1 || in.RequiredParams()[0] != "secrets" {
		t.Fatalf("unexpected required params")
	}
	if len(out.RequiredParams()) != 1 || out.RequiredParams()[0] != "secrets" {
		t.Fatalf("unexpected required params")
	}
	if got := out.OptionalParams(); len(got) != 2 || got[0] != "header" || got[1] != "prefix" {
		t.Fatalf("unexpected optional params: %v", got)
	}
}
