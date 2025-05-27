package integrationplugins

// CapabilityConfig defines a named capability and optional parameters.
type CapabilityConfig struct {
	Name   string                 `json:"name"`
	Params map[string]interface{} `json:"params"`
}

// CapabilitySpec converts capability params into call rules.
type CapabilitySpec struct {
	Params   []string
	Generate func(map[string]interface{}) ([]CallRule, error)
}

var capabilityRegistry = map[string]map[string]CapabilitySpec{}

func RegisterCapability(integration, name string, spec CapabilitySpec) {
	if capabilityRegistry[integration] == nil {
		capabilityRegistry[integration] = map[string]CapabilitySpec{}
	}
	capabilityRegistry[integration][name] = spec
}

func getCapability(integration, name string) (CapabilitySpec, bool) {
	m, ok := capabilityRegistry[integration]
	if !ok {
		return CapabilitySpec{}, false
	}
	spec, ok := m[name]
	return spec, ok
}

func CapabilitiesFor(integration string) map[string]CapabilitySpec {
	return capabilityRegistry[integration]
}

// expandCapabilities converts declared capabilities into explicit allow rules.
func ExpandCapabilities(integration string, callers []CallerConfig) []CallerConfig {
	for i := range callers {
		for _, cap := range callers[i].Capabilities {
			spec, ok := getCapability(integration, cap.Name)
			if !ok {
				continue
			}
			rules, err := spec.Generate(cap.Params)
			if err != nil {
				continue
			}
			callers[i].Rules = append(callers[i].Rules, rules...)
		}
		callers[i].Capabilities = nil
	}
	return callers
}

// ListCapabilities exposes capability names for CLI usage.
func AllCapabilities() map[string]map[string]CapabilitySpec {
	return capabilityRegistry
}
