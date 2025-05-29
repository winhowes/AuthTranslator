package integrationplugins

// CallRule ties a path pattern to method-specific constraints.
type CallRule struct {
	Path     string                       `json:"path"`
	Methods  map[string]RequestConstraint `json:"methods"`
	Segments []string                     `json:"-"`
}

// RequestConstraint lists required headers and body parameters.
type RequestConstraint struct {
	Headers map[string][]string    `json:"headers"`
	Query   map[string][]string    `json:"query"`
	Body    map[string]interface{} `json:"body"`
}

type CallerConfig struct {
	ID           string             `json:"id"`
	Capabilities []CapabilityConfig `json:"capabilities,omitempty"`
	Rules        []CallRule         `json:"rules"`
}
