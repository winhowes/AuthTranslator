package plugins

func init() {
	RegisterCapability("monday", "create_item", CapabilitySpec{})
	RegisterCapability("monday", "update_status", CapabilitySpec{})
	RegisterCapability("monday", "add_comment", CapabilitySpec{})
}
