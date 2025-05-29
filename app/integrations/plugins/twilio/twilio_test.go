package twilio_test

import (
	"testing"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/twilio"
)

func TestTwilioCapabilities(t *testing.T) {
	caps := integrationplugins.CapabilitiesFor("twilio")
	if len(caps) != 3 {
		t.Fatalf("expected 3 capabilities, got %d", len(caps))
	}

	tests := []struct {
		name   string
		path   string
		method string
	}{
		{"send_sms", "/2010-04-01/Accounts/*/Messages.json", "POST"},
		{"make_call", "/2010-04-01/Accounts/*/Calls.json", "POST"},
		{"query_message", "/2010-04-01/Accounts/*/Messages/*", "GET"},
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
