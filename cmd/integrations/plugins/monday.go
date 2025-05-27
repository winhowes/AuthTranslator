package plugins

import (
	"flag"
	"fmt"
)

// Monday returns an Integration configured for the monday.com API.
func Monday(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.monday.com/v2",
		InRateLimit:  100,
		OutRateLimit: 100,
		OutgoingAuth: []AuthPluginConfig{{
			Type: "token",
			Params: map[string]interface{}{
				"secrets": []string{tokenRef},
				"header":  "Authorization",
			},
		}},
	}
}

func init() { Register("monday", mondayBuilder) }

func mondayBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("monday", flag.ContinueOnError)
	name := fs.String("name", "monday", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return Monday(*name, *token), nil
}
