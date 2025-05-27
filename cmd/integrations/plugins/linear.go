package plugins

// Linear returns an Integration configured for the Linear API.
func Linear(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.linear.app",
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
