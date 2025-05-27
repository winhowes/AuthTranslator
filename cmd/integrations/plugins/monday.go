package plugins

// Monday returns an Integration configured for the monday.com API.
func Monday(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.monday.com/v2",
		InRateLimit:  100,
		OutRateLimit: 100,
		OutgoingAuth: []AuthPluginConfig{{
			Type: "token",
			Params: map[string]interface{}{
				"secrets": []string{tokenRef},
				"header":  "Authorization",
			},
		}},
	}
}
