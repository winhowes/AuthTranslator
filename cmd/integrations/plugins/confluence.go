package plugins

import (
	"flag"
	"fmt"
)

// Confluence returns an Integration configured for the Confluence API.
func Confluence(name, tokenRef string) Integration {
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

func init() { Register("confluence", confluenceBuilder) }

func confluenceBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("confluence", flag.ContinueOnError)
	name := fs.String("name", "confluence", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return Confluence(*name, *token), nil
}
