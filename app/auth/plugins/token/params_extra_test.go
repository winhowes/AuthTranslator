package token

import "testing"

func TestTokenParamsFuncs(t *testing.T) {
	in := &TokenAuth{}
	out := &TokenAuthOut{}
	if in.Name() != "token" || out.Name() != "token" {
		t.Fatalf("name mismatch")
	}
	if len(in.RequiredParams()) != 2 || in.RequiredParams()[0] != "secrets" {
		t.Fatalf("unexpected required params")
	}
	if len(out.RequiredParams()) != 2 || out.RequiredParams()[0] != "secrets" {
		t.Fatalf("unexpected required params")
	}
}

func TestTokenParseParamsError(t *testing.T) {
	in := &TokenAuth{}
	if _, err := in.ParseParams(map[string]interface{}{"header": "H"}); err == nil {
		t.Fatal("expected error")
	}
	out := &TokenAuthOut{}
	if _, err := out.ParseParams(map[string]interface{}{"header": "H"}); err == nil {
		t.Fatal("expected error")
	}
}
