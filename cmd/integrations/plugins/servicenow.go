package plugins

import (
	"flag"
	"fmt"
)

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

func init() { Register("servicenow", servicenowBuilder) }

func servicenowBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("servicenow", flag.ContinueOnError)
	name := fs.String("name", "servicenow", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return ServiceNow(*name, *token), nil
}
