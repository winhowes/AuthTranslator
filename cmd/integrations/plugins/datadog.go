package plugins

import (
	"flag"
	"fmt"
)

// Datadog returns an Integration configured for the Datadog API.
func Datadog(name, apiKeyRef, appKeyRef string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://api.datadoghq.com",
		InRateLimit:  100,
		OutRateLimit: 100,
		OutgoingAuth: []AuthPluginConfig{
			{
				Type: "token",
				Params: map[string]interface{}{
					"secrets": []string{apiKeyRef},
					"header":  "DD-API-KEY",
				},
			},
			{
				Type: "token",
				Params: map[string]interface{}{
					"secrets": []string{appKeyRef},
					"header":  "DD-APPLICATION-KEY",
				},
			},
		},
	}
}

func init() { Register("datadog", datadogBuilder) }

func datadogBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("datadog", flag.ContinueOnError)
	name := fs.String("name", "datadog", "integration name")
	api := fs.String("api-key", "", "secret reference for API key")
	app := fs.String("app-key", "", "secret reference for application key")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	if *api == "" || *app == "" {
		return Integration{}, fmt.Errorf("-api-key and -app-key are required")
	}
	return Datadog(*name, *api, *app), nil
}
