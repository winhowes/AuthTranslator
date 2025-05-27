package plugins

import (
	"fmt"
	"os"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// envPlugin loads secrets from environment variables.
type envPlugin struct{}

func (envPlugin) Prefix() string { return "env" }

func (envPlugin) Load(id string) (string, error) {
	val, ok := os.LookupEnv(id)
	if !ok {
		return "", fmt.Errorf("%s not set", id)
	}
	return val, nil
}

func init() { secrets.Register(envPlugin{}) }
