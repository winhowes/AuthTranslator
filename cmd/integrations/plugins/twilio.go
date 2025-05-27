package plugins

import (
	"flag"
	"fmt"
)

// Twilio returns an Integration configured for the Twilio API.
func Twilio(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.twilio.com",
		InRateLimit:  100,
		OutRateLimit: 100,
		OutgoingAuth: []AuthPluginConfig{{
			Type: "basic",
			Params: map[string]interface{}{
				"secrets": []string{tokenRef},
			},
		}},
	}
}

func init() { Register("twilio", twilioBuilder) }

func twilioBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("twilio", flag.ContinueOnError)
	name := fs.String("name", "twilio", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return Twilio(*name, *token), nil
}
