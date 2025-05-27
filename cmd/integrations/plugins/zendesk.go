package plugins

import (
	"flag"
	"fmt"
)

// Zendesk returns an Integration configured for the Zendesk API.
func Zendesk(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.zendesk.com",
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

func init() { Register("zendesk", zendeskBuilder) }

func zendeskBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("zendesk", flag.ContinueOnError)
	name := fs.String("name", "zendesk", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return Zendesk(*name, *token), nil
}
