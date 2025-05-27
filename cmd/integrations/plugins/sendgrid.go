package plugins

// SendGrid returns an Integration configured for the SendGrid API.
func SendGrid(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.sendgrid.com",
		InRateLimit:  100,
		OutRateLimit: 100,
		OutgoingAuth: []AuthPluginConfig{{
			Type: "token",
			Params: map[string]interface{}{
				"secrets": []string{tokenRef},
				"header":  "Authorization",
				"prefix":  "Bearer ",
			},
		}},
	}
}
