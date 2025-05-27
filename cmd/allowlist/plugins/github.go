package plugins

func init() {
	RegisterCapability("github", "comment", CapabilitySpec{
		Params: []string{"repo"},
	})
}
