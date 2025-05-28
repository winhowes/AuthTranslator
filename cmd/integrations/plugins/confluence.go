package plugins

import (
	"flag"
	"fmt"
	"strings"
)

// Confluence returns an Integration configured for the Confluence API. The domain
// argument is optional and defaults to api.atlassian.com.
func Confluence(name, tokenRef, domain string) Integration {
	if domain == "" {
		domain = "api.atlassian.com"
	}
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

func init() { Register("confluence", confluenceBuilder) }

func confluenceBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("confluence", flag.ContinueOnError)
	name := fs.String("name", "confluence", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	domain := fs.String("domain", "api.atlassian.com", "confluence domain")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return Confluence(*name, *token, *domain), nil
}
