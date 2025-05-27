package secrets

import (
	"fmt"
	"os"
	"strings"
)

// Plugin fetches a secret value for a given identifier.
type Plugin interface {
	Prefix() string
	Load(id string) (string, error)
}

var registry = make(map[string]Plugin)

// Register adds a secret plugin for a prefix.
func Register(p Plugin) { registry[p.Prefix()] = p }

// ValidateSecret checks that the reference uses a known prefix.
func ValidateSecret(ref string) error {
	parts := strings.SplitN(ref, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid secret reference: %s", ref)
	}
	prefix := parts[0]
	if _, ok := registry[prefix]; !ok {
		return fmt.Errorf("unknown secret source: %s", prefix)
	}
	return nil
}

// LoadSecret resolves a secret reference using the registered plugins.
func LoadSecret(ref string) (string, error) {
	parts := strings.SplitN(ref, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid secret reference: %s", ref)
	}
	prefix, id := parts[0], parts[1]
	p, ok := registry[prefix]
	if !ok {
		return "", fmt.Errorf("unknown secret source: %s", prefix)
	}
	return p.Load(id)
}

type envPlugin struct{}

func (envPlugin) Prefix() string                 { return "env" }
func (envPlugin) Load(id string) (string, error) { return os.Getenv(id), nil }

type kmsPlugin struct{ prefix string }

func (k kmsPlugin) Prefix() string                 { return k.prefix }
func (k kmsPlugin) Load(id string) (string, error) { return "kms-" + id, nil }

func init() {
	Register(envPlugin{})
	for _, p := range []string{"gcp", "aws", "oracle", "azure"} {
		Register(kmsPlugin{prefix: p})
	}
}
