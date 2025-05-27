package plugins

func init() {
	RegisterCapability("linear", "create_task", CapabilitySpec{})
	RegisterCapability("linear", "update_status", CapabilitySpec{})
	RegisterCapability("linear", "add_comment", CapabilitySpec{})
}
