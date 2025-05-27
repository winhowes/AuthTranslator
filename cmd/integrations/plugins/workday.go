package plugins

import (
	"flag"
	"fmt"
	"strings"
)

// Workday returns an Integration configured for the Workday API.
func Workday(name, domain, tokenRef string) Integration {
	if !strings.HasPrefix(domain, "https://") && !strings.HasPrefix(domain, "http://") {
		domain = "https://" + domain
	}
	dest := strings.TrimSuffix(domain, "/") + "/api"
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

func init() { Register("workday", workdayBuilder) }

func workdayBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("workday", flag.ContinueOnError)
	name := fs.String("name", "workday", "integration name")
	domain := fs.String("domain", "", "workday domain, e.g. myorg.workday.com")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" || *domain == "" {
		return Integration{}, fmt.Errorf("-token and -domain are required")
	}
	return Workday(*name, *domain, *token), nil
}
