package sendgrid_test

import (
	"testing"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/sendgrid"
)

func TestSendgridCapabilities(t *testing.T) {
	caps := integrationplugins.CapabilitiesFor("sendgrid")
	if len(caps) != 3 {
		t.Fatalf("expected 3 capabilities, got %d", len(caps))
	}

	tests := []struct {
		name   string
		path   string
		method string
	}{
		{"send_email", "/v3/mail/send", "POST"},
		{"manage_contacts", "/v3/marketing/contacts", "PUT"},
		{"update_template", "/v3/templates/*", "PATCH"},
	}

	for _, tt := range tests {
		spec, ok := caps[tt.name]
		if !ok {
			t.Fatalf("%s not registered", tt.name)
		}
		params := map[string]interface{}{}
		if tt.name == "send_email" {
			params = map[string]interface{}{"from": "me@example.com"}
		}
		rules, err := spec.Generate(params)
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
			continue
		}
		if tt.name == "send_email" {
			if rc.Body["from"] != "me@example.com" {
				t.Errorf("from not propagated")
			}
			v, ok := rc.Body["reply_to"].([]interface{})
			if !ok || len(v) != 2 || v[0] != "me@example.com" || v[1] != nil {
				t.Errorf("reply_to union unexpected: %#v", rc.Body["reply_to"])
			}
		}
	}

	spec := caps["send_email"]
	if _, err := spec.Generate(map[string]interface{}{}); err == nil {
		t.Errorf("expected error for missing from")
	}

	rules, err := spec.Generate(map[string]interface{}{"from": "me@example.com", "replyTo": "r@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rc := rules[0].Methods["POST"]
	if rc.Body["reply_to"] != "r@example.com" {
		t.Errorf("reply_to value not propagated")
	}

	rules, err = spec.Generate(map[string]interface{}{"from": "me@example.com", "replyTo": nil})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rc = rules[0].Methods["POST"]
	if rc.Body["reply_to"] != nil {
		t.Errorf("reply_to nil not set")
	}
}
