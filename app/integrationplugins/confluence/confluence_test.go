package confluence_test

import (
	"testing"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrationplugins"
	_ "github.com/winhowes/AuthTranslator/app/integrationplugins/confluence"
)

func TestConfluenceCapabilities(t *testing.T) {
	caps := integrationplugins.CapabilitiesFor("confluence")
	if len(caps) != 3 {
		t.Fatalf("expected 3 capabilities, got %d", len(caps))
	}

	tests := []struct {
		name     string
		wantPath string
		method   string
	}{
		{"create_page", "/wiki/api/v2/pages", "POST"},
		{"update_page", "/wiki/api/v2/pages/*", "PUT"},
		{"add_comment", "/wiki/api/v2/pages/*/comment", "POST"},
	}

	for _, tt := range tests {
		spec, ok := caps[tt.name]
		if !ok {
			t.Fatalf("capability %s not registered", tt.name)
		}
		rules, err := spec.Generate(nil)
		if err != nil {
			t.Fatalf("generate failed: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("expected 1 rule for %s", tt.name)
		}
		r := rules[0]
		if r.Path != tt.wantPath {
			t.Errorf("%s path mismatch: %s", tt.name, r.Path)
		}
		if _, ok := r.Methods[tt.method]; !ok {
			t.Errorf("%s missing method %s", tt.name, tt.method)
		}
	}
}
