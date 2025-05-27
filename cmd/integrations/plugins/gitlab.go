package plugins

import (
	"flag"
	"fmt"
)

// GitLab returns an Integration configured for the GitLab API.
func GitLab(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://gitlab.com/api/v4",
		InRateLimit:  100,
		OutRateLimit: 100,
		OutgoingAuth: []AuthPluginConfig{{
			Type: "token",
			Params: map[string]interface{}{
				"secrets": []string{tokenRef},
				"header":  "PRIVATE-TOKEN",
			},
		}},
	}
}

func init() { Register("gitlab", gitlabBuilder) }

func gitlabBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("gitlab", flag.ContinueOnError)
	name := fs.String("name", "gitlab", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return GitLab(*name, *token), nil
}
