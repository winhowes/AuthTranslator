//go:build example

package example

import (
	"flag"

	integrationplugins "github.com/winhowes/AuthTranslator/cmd/integrations/plugins"
)

// Example returns a minimal Integration used for demonstration purposes.
func Example(name string) integrationplugins.Integration {
	return integrationplugins.Integration{
		Name:        name,
		Destination: "http://example.com",
	}
}

func init() { integrationplugins.Register("example", builder) }

func builder(args []string) (integrationplugins.Integration, error) {
	fs := flag.NewFlagSet("example", flag.ContinueOnError)
	name := fs.String("name", "example", "integration name")
	if err := fs.Parse(args); err != nil {
		return integrationplugins.Integration{}, err
	}
	return Example(*name), nil
}
