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
			from, ok := rc.Body["from"].(map[string]interface{})
			if !ok || from["email"] != "me@example.com" {
				t.Errorf("from not propagated")
			}
			if _, ok := rc.Body["reply_to"]; ok {
				t.Errorf("reply_to default unexpected: %#v", rc.Body["reply_to"])
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
	replyTo, ok := rc.Body["reply_to"].(map[string]interface{})
	if !ok || replyTo["email"] != "r@example.com" {
		t.Errorf("reply_to value not propagated")
	}

	rules, err = spec.Generate(map[string]interface{}{"from": "me@example.com", "replyTo": nil})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rc = rules[0].Methods["POST"]
	if _, ok := rc.Body["reply_to"]; ok {
		t.Errorf("reply_to nil not set")
	}

	if _, err := spec.Generate(map[string]interface{}{"from": "me@example.com", "replyTo": 123}); err == nil {
		t.Errorf("expected error for non-string replyTo")
	}
}
