package plugins

// Slack returns an Integration configured for the Slack API.
func Slack(name, tokenRef, signingSecretRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://slack.com/api",
		InRateLimit:  100,
		OutRateLimit: 100,
		IncomingAuth: []AuthPluginConfig{{
			Type: "slack_signature",
			Params: map[string]interface{}{
				"secrets": []string{signingSecretRef},
			},
		}},
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
