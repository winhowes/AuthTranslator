package plugins

func init() {
	RegisterCapability("zendesk", "open_ticket", CapabilitySpec{})
	RegisterCapability("zendesk", "update_ticket", CapabilitySpec{})
	RegisterCapability("zendesk", "query_status", CapabilitySpec{})
}
