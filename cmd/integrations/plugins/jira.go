package plugins

// Jira returns an Integration configured for the Jira API.
func Jira(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.atlassian.com",
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
