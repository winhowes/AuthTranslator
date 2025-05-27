package plugins

import (
	"flag"
	"fmt"
)

// Stripe returns an Integration configured for the Stripe API.
func Stripe(name, tokenRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.stripe.com",
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

func init() { Register("stripe", stripeBuilder) }

func stripeBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("stripe", flag.ContinueOnError)
	name := fs.String("name", "stripe", "integration name")
	token := fs.String("token", "", "secret reference for API token")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *token == "" {
		return Integration{}, fmt.Errorf("-token is required")
	}
	return Stripe(*name, *token), nil
}
