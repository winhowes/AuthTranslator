package plugins

// AuthPluginConfig mirrors the main application's plugin config.
type AuthPluginConfig struct {
	Type   string                 `json:"type"`
	Params map[string]interface{} `json:"params"`
}

// Integration mirrors the main application's integration structure.
type Integration struct {
	Name           string             `json:"name"`
	Destination    string             `json:"destination"`
	InRateLimit    int                `json:"in_rate_limit"`
	OutRateLimit   int                `json:"out_rate_limit"`
	IncomingAuth   []AuthPluginConfig `json:"incoming_auth"`
	OutgoingAuth   []AuthPluginConfig `json:"outgoing_auth"`
	AllowedCallers []struct{}         `json:"allowlist,omitempty"`
}
