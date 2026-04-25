package plugins

import (
	"reflect"
	"strings"
	"testing"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
)

// Test that plugin init functions register their capabilities into the registry.
func TestRegistryInitialization(t *testing.T) {
	list := List()
	if len(list) == 0 {
		t.Fatalf("registry is empty")
	}
	slack, ok := list["slack"]
	if !ok {
		t.Fatalf("slack capabilities missing")
	}
	if spec, ok := slack["post_as"]; !ok {
		t.Fatalf("post_as capability missing")
	} else if !reflect.DeepEqual(spec.Params, []string{"username"}) {
		t.Fatalf("unexpected post_as params: %v", spec.Params)
	}
	if spec, ok := slack["post_channels_as"]; !ok {
		t.Fatalf("post_channels_as capability missing")
	} else if !reflect.DeepEqual(spec.Params, []string{"username", "channels"}) {
		t.Fatalf("unexpected post_channels_as params: %v", spec.Params)
	}
	if spec, ok := slack["post_channels"]; !ok {
		t.Fatalf("post_channels capability missing")
	} else if !reflect.DeepEqual(spec.Params, []string{"channels"}) {
		t.Fatalf("unexpected post_channels params: %v", spec.Params)
	}

	github, ok := list["github"]
	if !ok {
		t.Fatalf("github capabilities missing")
	}
	if spec, ok := github["comment"]; !ok {
		t.Fatalf("github comment capability missing")
	} else if !reflect.DeepEqual(spec.Params, []string{"repo"}) {
		t.Fatalf("unexpected github comment params: %v", spec.Params)
	}
	if spec, ok := github["create_issue"]; !ok {
		t.Fatalf("github create_issue capability missing")
	} else if !reflect.DeepEqual(spec.Params, []string{"repo"}) {
		t.Fatalf("unexpected github create_issue params: %v", spec.Params)
	}

	openai, ok := list["openai"]
	if !ok {
		t.Fatalf("openai capabilities missing")
	}
	if _, ok := openai["chat_completion"]; !ok {
		t.Fatalf("openai chat_completion capability missing")
	}
}

func TestValidateCapability(t *testing.T) {
	if err := ValidateCapability("github", CapabilityConfig{Name: "comment", Params: map[string]interface{}{"repo": "org/repo"}}); err != nil {
		t.Fatalf("expected valid capability: %v", err)
	}
	if err := ValidateCapability("github", CapabilityConfig{Name: integrationplugins.DangerouslyAllowFullAccess}); err != nil {
		t.Fatalf("expected global capability to be valid: %v", err)
	}
	if err := ValidateCapability("github", CapabilityConfig{Name: "missing"}); err == nil {
		t.Fatalf("expected unknown capability error")
	}
	if err := ValidateCapability("github", CapabilityConfig{Name: "comment", Params: map[string]interface{}{"bogus": "x"}}); err == nil {
		t.Fatalf("expected unknown param error")
	}
	if err := ValidateCapability("github", CapabilityConfig{Name: "comment"}); err == nil {
		t.Fatalf("expected missing repo error")
	}
	if err := ValidateCapability("github", CapabilityConfig{Name: "comment", Params: map[string]interface{}{"repo": "org/repo"}}); err != nil {
		t.Fatalf("expected valid capability after errors: %v", err)
	}
}

func TestCapabilityNoGlobalRegistryFallback(t *testing.T) {
	restore := snapshotRegistry(t)
	defer restore()

	reg := integrationplugins.AllCapabilities()
	delete(reg, integrationplugins.GlobalIntegration)

	if _, ok := Capability("missing", "missing"); ok {
		t.Fatal("expected missing capability when integration and global registry are absent")
	}
}

func TestValidateCapabilityWithoutGenerator(t *testing.T) {
	restore := snapshotRegistry(t)
	defer restore()

	integrationplugins.RegisterCapability("registrytest", "nogenerator", integrationplugins.CapabilitySpec{})
	err := ValidateCapability("registrytest", CapabilityConfig{Name: "nogenerator"})
	if err == nil || !strings.Contains(err.Error(), "has no rule generator") {
		t.Fatalf("expected no rule generator error, got %v", err)
	}
}

func snapshotRegistry(t *testing.T) func() {
	t.Helper()

	orig := make(map[string]map[string]integrationplugins.CapabilitySpec)
	for integ, caps := range integrationplugins.AllCapabilities() {
		m := make(map[string]integrationplugins.CapabilitySpec, len(caps))
		for name, spec := range caps {
			m[name] = spec
		}
		orig[integ] = m
	}
	return func() {
		reg := integrationplugins.AllCapabilities()
		for k := range reg {
			delete(reg, k)
		}
		for k, v := range orig {
			reg[k] = v
		}
	}
}
