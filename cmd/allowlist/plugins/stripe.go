package plugins

func init() {
	RegisterCapability("stripe", "create_charge", CapabilitySpec{})
	RegisterCapability("stripe", "refund_charge", CapabilitySpec{})
	RegisterCapability("stripe", "create_customer", CapabilitySpec{})
}
