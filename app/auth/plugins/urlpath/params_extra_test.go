package urlpath

import "testing"

func TestURLPathParamsFuncs(t *testing.T) {
	in := &URLPathAuth{}
	out := &URLPathAuthOut{}
	if in.Name() != "url_path" || out.Name() != "url_path" {
		t.Fatalf("name mismatch")
	}
	if len(in.RequiredParams()) != 1 || in.RequiredParams()[0] != "secrets" {
		t.Fatalf("unexpected required params")
	}
	if len(out.RequiredParams()) != 1 || out.RequiredParams()[0] != "secrets" {
		t.Fatalf("unexpected required params")
	}
}

func TestURLPathParseParamsErrorOut(t *testing.T) {
	out := &URLPathAuthOut{}
	if _, err := out.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error")
	}
}
