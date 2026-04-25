package plugins

import (
	"fmt"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins"
)

// CapabilitySpec describes a capability's parameters and rule generator.
type CapabilitySpec = integrationplugins.CapabilitySpec

func List() map[string]map[string]CapabilitySpec {
	return integrationplugins.AllCapabilities()
}

func Capability(integration, name string) (CapabilitySpec, bool) {
	if caps := integrationplugins.CapabilitiesFor(integration); caps != nil {
		if spec, ok := caps[name]; ok {
			return spec, true
		}
	}
	if caps := integrationplugins.CapabilitiesFor(integrationplugins.GlobalIntegration); caps != nil {
		spec, ok := caps[name]
		return spec, ok
	}
	return CapabilitySpec{}, false
}

func ValidateCapability(integration string, cap CapabilityConfig) error {
	spec, ok := Capability(integration, cap.Name)
	if !ok {
		return fmt.Errorf("unknown capability %s for integration %s", cap.Name, integration)
	}
	for param := range cap.Params {
		if !knownParam(spec.Params, param) {
			return fmt.Errorf("unknown param %s for capability %s", param, cap.Name)
		}
	}
	if spec.Generate == nil {
		return fmt.Errorf("capability %s has no rule generator", cap.Name)
	}
	if _, err := spec.Generate(cap.Params); err != nil {
		return fmt.Errorf("invalid params for capability %s: %w", cap.Name, err)
	}
	return nil
}

func knownParam(params []string, name string) bool {
	for _, param := range params {
		if param == name {
			return true
		}
	}
	return false
}
