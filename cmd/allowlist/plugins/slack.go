package plugins

func init() {
	RegisterCapability("slack", "post_as", CapabilitySpec{Params: []string{"username"}})
	RegisterCapability("slack", "post_channels_as", CapabilitySpec{Params: []string{"username", "channels"}})
	RegisterCapability("slack", "post_channels", CapabilitySpec{Params: []string{"channels"}})
}
