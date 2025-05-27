package secrets

import "os"

// envPlugin loads secrets from environment variables.
type envPlugin struct{}

func (envPlugin) Prefix() string { return "env" }

func (envPlugin) Load(id string) (string, error) { return os.Getenv(id), nil }

func init() { Register(envPlugin{}) }
