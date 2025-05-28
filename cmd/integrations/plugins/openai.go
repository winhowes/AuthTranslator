package plugins

import (
	"flag"
	"fmt"
)

// OpenAI returns an Integration configured for the OpenAI API.
func OpenAI(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.openai.com",
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

func init() { Register("openai", openaiBuilder) }

func openaiBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("openai", flag.ContinueOnError)
	name := fs.String("name", "openai", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return OpenAI(*name, *token), nil
}
