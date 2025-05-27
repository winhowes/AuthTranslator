package plugins

func init() {
	RegisterCapability("sendgrid", "send_email", CapabilitySpec{})
	RegisterCapability("sendgrid", "manage_contacts", CapabilitySpec{})
	RegisterCapability("sendgrid", "update_template", CapabilitySpec{})
}
