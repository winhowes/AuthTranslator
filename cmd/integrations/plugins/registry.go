package plugins

import "strings"

// Builder defines a function that parses CLI args into an Integration.
type Builder func(args []string) (Integration, error)

var registry = map[string]Builder{}

// Register adds a plugin builder to the registry.
func Register(name string, b Builder) { registry[strings.ToLower(name)] = b }

// Get retrieves a registered builder by name.
func Get(name string) Builder { return registry[strings.ToLower(name)] }

// List returns the registered plugin names.
func List() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	return names
}
