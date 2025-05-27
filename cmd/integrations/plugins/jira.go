package plugins

import (
	"flag"
	"fmt"
)

// Jira returns an Integration configured for the Jira API.
func Jira(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.atlassian.com",
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

func init() { Register("jira", jiraBuilder) }

func jiraBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("jira", flag.ContinueOnError)
	name := fs.String("name", "jira", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return Jira(*name, *token), nil
}
