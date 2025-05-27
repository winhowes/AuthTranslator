package plugins

import (
	"flag"
	"fmt"
	"strings"
)

// Okta returns an Integration configured for the Okta API.
func Okta(name, domain, tokenRef string) Integration {
	if !strings.HasPrefix(domain, "https://") && !strings.HasPrefix(domain, "http://") {
		domain = "https://" + domain
	}
	dest := strings.TrimSuffix(domain, "/") + "/api/v1"
	return Integration{
		Name:         name,
		Destination:  dest,
		InRateLimit:  100,
		OutRateLimit: 100,
		OutgoingAuth: []AuthPluginConfig{{
			Type: "token",
			Params: map[string]interface{}{
				"secrets": []string{tokenRef},
				"header":  "Authorization",
				"prefix":  "SSWS ",
			},
		}},
	}
}

func init() { Register("okta", oktaBuilder) }

func oktaBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("okta", flag.ContinueOnError)
	name := fs.String("name", "okta", "integration name")
	domain := fs.String("domain", "", "okta domain, e.g. myorg.okta.com")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" || *domain == "" {
		return Integration{}, fmt.Errorf("-token and -domain are required")
	}
	return Okta(*name, *domain, *token), nil
}
