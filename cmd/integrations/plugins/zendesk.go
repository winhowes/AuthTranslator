package plugins

// Zendesk returns an Integration configured for the Zendesk API.
func Zendesk(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.zendesk.com",
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
