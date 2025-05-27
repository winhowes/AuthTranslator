package plugins

// Twilio returns an Integration configured for the Twilio API.
func Twilio(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.twilio.com",
		InRateLimit:  100,
		OutRateLimit: 100,
		OutgoingAuth: []AuthPluginConfig{{
			Type: "basic",
			Params: map[string]interface{}{
				"secrets": []string{tokenRef},
			},
		}},
	}
}
