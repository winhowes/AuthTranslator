package plugins

import (
	"flag"
	"fmt"
)

// TruffleHog returns an Integration configured for the TruffleHog API.
func TruffleHog(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://trufflehog.cloud/api",
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

func init() { Register("trufflehog", trufflehogBuilder) }

func trufflehogBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("trufflehog", flag.ContinueOnError)
	name := fs.String("name", "trufflehog", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return TruffleHog(*name, *token), nil
}
