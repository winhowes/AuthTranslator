package plugins

func init() {
	RegisterCapability("jira", "create_task", CapabilitySpec{})
	RegisterCapability("jira", "update_status", CapabilitySpec{})
	RegisterCapability("jira", "add_comment", CapabilitySpec{})
}
