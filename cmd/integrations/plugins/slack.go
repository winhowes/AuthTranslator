package plugins

import (
	"flag"
	"fmt"
)

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

func init() { Register("slack", slackBuilder) }

func slackBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("slack", flag.ContinueOnError)
	name := fs.String("name", "slack", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	sign := fs.String("signing-secret", "", "secret reference for signing secret")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" || *sign == "" {
		return Integration{}, fmt.Errorf("-token and -signing-secret are required")
	}
	return Slack(*name, *token, *sign), nil
}
