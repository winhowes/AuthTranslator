package plugins

// GitHub returns an Integration configured for the GitHub API.
func GitHub(name, tokenRef, webhookSecretRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.github.com",
		InRateLimit:  100,
		OutRateLimit: 100,
		IncomingAuth: []AuthPluginConfig{{
			Type: "github_signature",
			Params: map[string]interface{}{
				"secrets": []string{webhookSecretRef},
			},
		}},
		OutgoingAuth: []AuthPluginConfig{{
			Type: "token",
			Params: map[string]interface{}{
				"secrets": []string{tokenRef},
				"header":  "Authorization",
				"prefix":  "token ",
			},
		}},
	}
}
