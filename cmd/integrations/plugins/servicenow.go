package plugins

import (
	"flag"
	"fmt"
	"strings"
)

// ServiceNow returns an Integration configured for the ServiceNow API.
func ServiceNow(name, domain, tokenRef string) Integration {
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

func init() { Register("servicenow", servicenowBuilder) }

func servicenowBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("servicenow", flag.ContinueOnError)
	name := fs.String("name", "servicenow", "integration name")
	domain := fs.String("domain", "", "ServiceNow instance domain, e.g. example.service-now.com")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" || *domain == "" {
		return Integration{}, fmt.Errorf("-token and -domain are required")
	}
	return ServiceNow(*name, *domain, *token), nil
}
