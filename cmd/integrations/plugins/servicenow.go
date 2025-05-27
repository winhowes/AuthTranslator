package plugins

// ServiceNow returns an Integration configured for the ServiceNow API.
func ServiceNow(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.servicenow.com",
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
