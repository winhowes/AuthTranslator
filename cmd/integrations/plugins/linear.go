package plugins

import (
	"flag"
	"fmt"
)

// Linear returns an Integration configured for the Linear API.
func Linear(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.linear.app",
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

func init() { Register("linear", linearBuilder) }

func linearBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("linear", flag.ContinueOnError)
	name := fs.String("name", "linear", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return Linear(*name, *token), nil
}
