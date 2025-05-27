package plugins

import (
	"flag"
	"fmt"
)

// SendGrid returns an Integration configured for the SendGrid API.
func SendGrid(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.sendgrid.com",
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

func init() { Register("sendgrid", sendgridBuilder) }

func sendgridBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("sendgrid", flag.ContinueOnError)
	name := fs.String("name", "sendgrid", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return SendGrid(*name, *token), nil
}
