package plugins

// AuthPluginConfig mirrors the main application's plugin config.
type AuthPluginConfig struct {
	Type   string                 `json:"type" yaml:"type"`
	Params map[string]interface{} `json:"params" yaml:"params"`
}

// Integration mirrors the main application's integration structure.
type Integration struct {
	Name         string             `json:"name" yaml:"name"`
	Destination  string             `json:"destination" yaml:"destination"`
	InRateLimit  int                `json:"in_rate_limit" yaml:"in_rate_limit"`
	OutRateLimit int                `json:"out_rate_limit" yaml:"out_rate_limit"`
	IncomingAuth []AuthPluginConfig `json:"incoming_auth" yaml:"incoming_auth"`
	OutgoingAuth []AuthPluginConfig `json:"outgoing_auth" yaml:"outgoing_auth"`
}
