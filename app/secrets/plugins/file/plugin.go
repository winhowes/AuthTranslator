package plugins

import (
	"os"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// filePlugin reads secrets from files on disk.
type filePlugin struct{}

func (filePlugin) Prefix() string { return "file" }

func (filePlugin) Load(id string) (string, error) {
	b, err := os.ReadFile(id)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func init() { secrets.Register(filePlugin{}) }
