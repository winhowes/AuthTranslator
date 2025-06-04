package plugins

import (
	"flag"
	"fmt"
)

// PagerDuty returns an Integration configured for the PagerDuty API.
func PagerDuty(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.pagerduty.com",
		InRateLimit:  100,
		OutRateLimit: 100,
		OutgoingAuth: []AuthPluginConfig{{
			Type: "token",
			Params: map[string]interface{}{
				"secrets": []string{tokenRef},
				"header":  "Authorization",
				"prefix":  "Token token=",
			},
		}},
	}
}

func init() { Register("pagerduty", pagerdutyBuilder) }

func pagerdutyBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("pagerduty", flag.ContinueOnError)
	name := fs.String("name", "pagerduty", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return PagerDuty(*name, *token), nil
}
