package plugins

func init() {
	RegisterCapability("twilio", "send_sms", CapabilitySpec{})
	RegisterCapability("twilio", "make_call", CapabilitySpec{})
	RegisterCapability("twilio", "query_message", CapabilitySpec{})
}
