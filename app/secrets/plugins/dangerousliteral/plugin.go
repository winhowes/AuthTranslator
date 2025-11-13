package plugins

import (
	"context"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// dangerousLiteralPlugin echoes the provided identifier. Useful for matching
// literal placeholders where storing the find value as a secret isn't
// practical. Do not use for real secrets since the value is stored in config.
type dangerousLiteralPlugin struct{}

func (dangerousLiteralPlugin) Prefix() string { return "dangerousLiteral" }

func (dangerousLiteralPlugin) Load(ctx context.Context, id string) (string, error) {
	return id, nil
}

func init() { secrets.Register(dangerousLiteralPlugin{}) }
