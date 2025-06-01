package integrationplugins

// CallRule ties a path pattern to method-specific constraints.
type CallRule struct {
	Path     string                       `json:"path" yaml:"path"`
	Methods  map[string]RequestConstraint `json:"methods" yaml:"methods,omitempty"`
	Segments []string                     `json:"-" yaml:"-"`
}

// RequestConstraint lists required headers and body parameters.
type RequestConstraint struct {
	Headers map[string][]string    `json:"headers" yaml:"headers,omitempty"`
	Query   map[string][]string    `json:"query" yaml:"query,omitempty"`
	Body    map[string]interface{} `json:"body" yaml:"body,omitempty"`
}

type CallerConfig struct {
	ID           string             `json:"id" yaml:"id"`
	Capabilities []CapabilityConfig `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Rules        []CallRule         `json:"rules" yaml:"rules,omitempty"`
}
