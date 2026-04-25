package monday_test

import (
	"testing"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/monday"
)

func TestMondayCapabilities(t *testing.T) {
	caps := integrationplugins.CapabilitiesFor("monday")
	if len(caps) != 3 {
		t.Fatalf("expected 3 capabilities, got %d", len(caps))
	}

	tests := []struct {
		name          string
		path          string
		method        string
		operationName string
	}{
		{"create_item", "/v2", "POST", "create_item"},
		{"update_status", "/v2", "POST", "update_status"},
		{"add_comment", "/v2", "POST", "add_comment"},
	}

	for _, tt := range tests {
		spec, ok := caps[tt.name]
		if !ok {
			t.Fatalf("%s not registered", tt.name)
		}
		rules, err := spec.Generate(nil)
		if err != nil {
			t.Fatalf("generate failed: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("expected 1 rule for %s", tt.name)
		}
		r := rules[0]
		if r.Path != tt.path {
			t.Errorf("%s path mismatch: %s", tt.name, r.Path)
		}
		rc, ok := r.Methods[tt.method]
		if !ok {
			t.Errorf("%s missing method %s", tt.name, tt.method)
		}
		if rc.Body["operationName"] != tt.operationName {
			t.Errorf("%s operationName mismatch: %v", tt.name, rc.Body["operationName"])
		}

		rules, err = spec.Generate(map[string]interface{}{})
		if err != nil {
			t.Fatalf("generate empty params failed: %v", err)
		}
		if got := rules[0].Methods[tt.method].Body["operationName"]; got != tt.operationName {
			t.Errorf("%s empty operationName fallback mismatch: %v", tt.name, got)
		}

		rules, err = spec.Generate(map[string]interface{}{"operationName": "customOp"})
		if err != nil {
			t.Fatalf("generate custom operation failed: %v", err)
		}
		if got := rules[0].Methods[tt.method].Body["operationName"]; got != "customOp" {
			t.Errorf("%s custom operationName mismatch: %v", tt.name, got)
		}
	}
}
