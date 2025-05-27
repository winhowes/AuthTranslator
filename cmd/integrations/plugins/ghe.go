package plugins

import (
	"flag"
	"fmt"
)

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

func init() { Register("ghe", gheBuilder) }

func gheBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("ghe", flag.ContinueOnError)
	name := fs.String("name", "ghe", "integration name")
	domain := fs.String("domain", "", "GitHub Enterprise domain")
	token := fs.String("token", "", "secret reference for API token")
	secret := fs.String("webhook-secret", "", "secret reference for webhook secret")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *domain == "" || *token == "" || *secret == "" {
		return Integration{}, fmt.Errorf("-domain, -token and -webhook-secret are required")
	}
	return GitHubEnterprise(*name, *domain, *token, *secret), nil
}
