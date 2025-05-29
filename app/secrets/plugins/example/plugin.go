//go:build example

package example

import (
	"context"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// plugin is a minimal secret plugin used for demonstration.
type plugin struct{}

func (plugin) Prefix() string { return "example" }

// Load simply returns the provided id as the secret value.
func (plugin) Load(ctx context.Context, id string) (string, error) {
	return id, nil
}

func init() { secrets.Register(plugin{}) }
