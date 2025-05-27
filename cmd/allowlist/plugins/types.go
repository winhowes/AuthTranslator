package plugins

// CallerConfig mirrors the server structure for CLI use.
type CallerConfig struct {
	ID           string             `json:"id"`
	Capabilities []CapabilityConfig `json:"capabilities,omitempty"`
	Rules        []CallRule         `json:"rules"`
}

type CapabilityConfig struct {
	Name   string                 `json:"name"`
	Params map[string]interface{} `json:"params"`
}

type CallRule struct {
	Path    string                       `json:"path"`
	Methods map[string]RequestConstraint `json:"methods"`
}

type RequestConstraint struct {
	Headers []string               `json:"headers"`
	Body    map[string]interface{} `json:"body"`
}

type AllowlistEntry struct {
	Integration string         `json:"integration"`
	Callers     []CallerConfig `json:"callers"`
}
