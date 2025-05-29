package plugins

// CallerConfig mirrors the server structure for CLI use.
type CallerConfig struct {
	ID           string             `json:"id" yaml:"id"`
	Capabilities []CapabilityConfig `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Rules        []CallRule         `json:"rules,omitempty" yaml:"rules,omitempty"`
}

type CapabilityConfig struct {
	Name   string                 `json:"name" yaml:"name"`
	Params map[string]interface{} `json:"params" yaml:"params"`
}

type CallRule struct {
	Path    string                       `json:"path" yaml:"path"`
	Methods map[string]RequestConstraint `json:"methods,omitempty" yaml:"methods,omitempty"`
}

type RequestConstraint struct {
	Headers map[string][]string    `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body    map[string]interface{} `json:"body,omitempty" yaml:"body,omitempty"`
}

type AllowlistEntry struct {
	Integration string         `json:"integration" yaml:"integration"`
	Callers     []CallerConfig `json:"callers,omitempty" yaml:"callers,omitempty"`
}
