package plugins

import (
	"flag"
	"fmt"
	"strings"
)

// Zendesk returns an Integration configured for the Zendesk API.
func Zendesk(name, domain, tokenRef string) Integration {
	if !strings.HasPrefix(domain, "https://") && !strings.HasPrefix(domain, "http://") {
		domain = "https://" + domain
	}
	dest := strings.TrimSuffix(domain, "/")
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
				"prefix":  "Bearer ",
			},
		}},
	}
}

func init() { Register("zendesk", zendeskBuilder) }

func zendeskBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("zendesk", flag.ContinueOnError)
	name := fs.String("name", "zendesk", "integration name")
	domain := fs.String("domain", "", "Zendesk domain, e.g. example.zendesk.com")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" || *domain == "" {
		return Integration{}, fmt.Errorf("-token and -domain are required")
	}
	return Zendesk(*name, *domain, *token), nil
}
