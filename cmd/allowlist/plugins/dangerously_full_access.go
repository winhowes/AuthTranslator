package plugins

func init() {
	RegisterCapability("*", "dangerously_allow_full_access", CapabilitySpec{})
}
