package plugins

import (
	"flag"
	"fmt"
)

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

func init() { Register("github", githubBuilder) }

func githubBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("github", flag.ContinueOnError)
	name := fs.String("name", "github", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	secret := fs.String("webhook-secret", "", "secret reference for webhook secret")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" || *secret == "" {
		return Integration{}, fmt.Errorf("-token and -webhook-secret are required")
	}
	return GitHub(*name, *token, *secret), nil
}
