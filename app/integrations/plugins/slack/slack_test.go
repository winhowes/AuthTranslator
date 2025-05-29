package slack_test

import (
	"reflect"
	"testing"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/slack"
)

func TestSlackCapabilities(t *testing.T) {
	caps := integrationplugins.CapabilitiesFor("slack")
	if len(caps) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(caps))
	}

	spec, ok := caps["post_public_as"]
	if !ok {
		t.Fatalf("post_public_as not registered")
	}
	rules, err := spec.Generate(map[string]interface{}{"username": "bot"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	rule := rules[0]
	if rule.Path != "/chat.postMessage" {
		t.Errorf("unexpected path %s", rule.Path)
	}
	rc, ok := rule.Methods["POST"]
	if !ok {
		t.Fatalf("missing POST method")
	}
	if rc.Body["username"] != "bot" {
		t.Errorf("username not propagated")
	}

	// missing username should error
	if _, err := spec.Generate(map[string]interface{}{}); err == nil {
		t.Errorf("expected error for missing username")
	}

	spec2, ok := caps["post_channels_as"]
	if !ok {
		t.Fatalf("post_channels_as not registered")
	}
	params := map[string]interface{}{
		"username": "bot",
		"channels": []interface{}{"c1", "c2"},
	}
	rules, err = spec2.Generate(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	rule = rules[0]
	rc, ok = rule.Methods["POST"]
	if !ok {
		t.Fatalf("missing POST method")
	}
	chVal, ok := rc.Body["channel"].([]interface{})
	if !ok || !reflect.DeepEqual(chVal, []interface{}{"c1", "c2"}) {
		t.Errorf("channels not propagated: %v", rc.Body["channel"])
	}

	// missing fields should error
	if _, err := spec2.Generate(map[string]interface{}{"username": "bot"}); err == nil {
		t.Errorf("expected error for missing channels")
	}
}
