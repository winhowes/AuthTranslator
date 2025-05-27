package plugins

func init() {
	RegisterCapability("okta", "create_user", CapabilitySpec{})
	RegisterCapability("okta", "update_user", CapabilitySpec{})
	RegisterCapability("okta", "deactivate_user", CapabilitySpec{})
}
