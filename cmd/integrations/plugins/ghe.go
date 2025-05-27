package plugins

import "fmt"

// GitHubEnterprise returns an Integration configured for a GitHub Enterprise instance.
func GitHubEnterprise(name, domain, tokenRef, webhookSecretRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  fmt.Sprintf("https://%s/api/v3", domain),
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
