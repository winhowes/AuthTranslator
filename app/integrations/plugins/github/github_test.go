package github_test

import (
	"testing"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/github"
)

func TestGithubCapabilities(t *testing.T) {
	caps := integrationplugins.CapabilitiesFor("github")
	if len(caps) != 3 {
		t.Fatalf("expected 3 capabilities, got %d", len(caps))
	}

	tests := []struct {
		name   string
		path   string
		method string
	}{
		{"comment", "/repos/r/issues/*/comments", "POST"},
		{"create_issue", "/repos/r/issues", "POST"},
		{"update_issue", "/repos/r/issues/*", "PATCH"},
	}

	for _, tt := range tests {
		spec, ok := caps[tt.name]
		if !ok {
			t.Fatalf("%s not registered", tt.name)
		}
		params := map[string]interface{}{"repo": "r"}
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
		if _, ok := r.Methods[tt.method]; !ok {
			t.Errorf("%s missing method %s", tt.name, tt.method)
		}

		if _, err := spec.Generate(nil); err == nil {
			t.Errorf("expected error for missing repo in %s", tt.name)
		}
	}
}
