package plugins

// CapabilitySpec describes a capability's parameters.
type CapabilitySpec struct {
	Params []string
}

var registry = map[string]map[string]CapabilitySpec{}

func RegisterCapability(integration, name string, spec CapabilitySpec) {
	if registry[integration] == nil {
		registry[integration] = map[string]CapabilitySpec{}
	}
	registry[integration][name] = spec
}

func List() map[string]map[string]CapabilitySpec {
	return registry
}
