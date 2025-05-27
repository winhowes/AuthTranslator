package plugins

// GitLab returns an Integration configured for the GitLab API.
func GitLab(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://gitlab.com/api/v4",
		InRateLimit:  100,
		OutRateLimit: 100,
		OutgoingAuth: []AuthPluginConfig{{
			Type: "token",
			Params: map[string]interface{}{
				"secrets": []string{tokenRef},
				"header":  "PRIVATE-TOKEN",
			},
		}},
	}
}
