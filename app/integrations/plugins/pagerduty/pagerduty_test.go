package pagerduty_test

import (
	"testing"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/pagerduty"
)

func TestPagerDutyCapabilities(t *testing.T) {
	caps := integrationplugins.CapabilitiesFor("pagerduty")
	if len(caps) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(caps))
	}

	tests := []struct {
		name   string
		path   string
		method string
	}{
		{"trigger_incident", "/incidents", "POST"},
		{"resolve_incident", "/incidents/*", "PUT"},
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
		if _, ok := r.Methods[tt.method]; !ok {
			t.Errorf("%s missing method %s", tt.name, tt.method)
		}
	}
}
