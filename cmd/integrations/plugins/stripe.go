package plugins

// Stripe returns an Integration configured for the Stripe API.
func Stripe(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.stripe.com",
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
