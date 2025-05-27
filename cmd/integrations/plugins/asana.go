package plugins

import (
	"flag"
	"fmt"
)

// Asana returns an Integration configured for the Asana API.
func Asana(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://app.asana.com/api/1.0",
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

func init() { Register("asana", asanaBuilder) }

func asanaBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("asana", flag.ContinueOnError)
	name := fs.String("name", "asana", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return Asana(*name, *token), nil
}
