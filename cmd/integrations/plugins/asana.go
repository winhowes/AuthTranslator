package plugins

// Asana returns an Integration configured for the Asana API.
func Asana(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://app.asana.com/api/1.0",
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
