package authplugins

import "testing"

// sample struct for parsing
type sampleParams struct {
	A string `json:"a"`
	B int    `json:"b"`
}

func TestParseParamsSuccess(t *testing.T) {
	m := map[string]interface{}{"a": "foo", "b": 2}
	cfg, err := ParseParams[sampleParams](m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.A != "foo" || cfg.B != 2 {
		t.Fatalf("unexpected result: %#v", cfg)
	}
}

func TestParseParamsUnknownField(t *testing.T) {
	m := map[string]interface{}{"a": "foo", "b": 2, "c": true}
	if _, err := ParseParams[sampleParams](m); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestParseParamsTypeMismatch(t *testing.T) {
	m := map[string]interface{}{"a": "foo", "b": "bad"}
	if _, err := ParseParams[sampleParams](m); err == nil {
		t.Fatal("expected type error")
	}
}

func TestParseParamsMarshalError(t *testing.T) {
	m := map[string]interface{}{"bad": func() {}}
	type badStruct struct {
		Bad string `json:"bad"`
	}
	if _, err := ParseParams[badStruct](m); err == nil {
		t.Fatal("expected marshal error")
	}
}
