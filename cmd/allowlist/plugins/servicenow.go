package plugins

func init() {
	RegisterCapability("servicenow", "open_ticket", CapabilitySpec{})
	RegisterCapability("servicenow", "update_ticket", CapabilitySpec{})
	RegisterCapability("servicenow", "query_status", CapabilitySpec{})
}
