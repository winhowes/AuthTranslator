package plugins

func init() {
	RegisterCapability("asana", "create_task", CapabilitySpec{})
	RegisterCapability("asana", "update_status", CapabilitySpec{})
	RegisterCapability("asana", "add_comment", CapabilitySpec{})
}
