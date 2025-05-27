package plugins

func init() {
	RegisterCapability("slack", "post_public_as", CapabilitySpec{Params: []string{"username"}})
	RegisterCapability("slack", "post_channels_as", CapabilitySpec{Params: []string{"username", "channels"}})
}
