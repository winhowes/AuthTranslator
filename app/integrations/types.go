package integrationplugins

// CallRule ties a path pattern to method-specific constraints.
type CallRule struct {
	Path     string                       `json:"path"`
	Methods  map[string]RequestConstraint `json:"methods"`
	Segments []string                     `json:"-"`
}

// RequestConstraint lists required headers and body parameters.
type RequestConstraint struct {
	Headers []string               `json:"headers"`
	Body    map[string]interface{} `json:"body"`
}

type CallerConfig struct {
	ID           string             `json:"id"`
	Capabilities []CapabilityConfig `json:"capabilities,omitempty"`
	Rules        []CallRule         `json:"rules"`
}
